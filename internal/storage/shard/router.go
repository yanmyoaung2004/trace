package shard

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/router"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// Instance is a single TSE shard with its own storage stack.
type Instance struct {
	ID       int
	Dir      string
	Hot      *sqlite.SQLiteHotStore
	Manifest *manifestpkg.Manifest
	Parquet  *parquet.ParquetWriter
	Flusher  *flusher.Flusher
	Router   *router.Router
	Reader   cold.ColdReader
}

// Config controls sharding.
type Config struct {
	NumShards    int    // number of shards
	BaseDir      string // base directory for all shard data
	FlushSize    int    // flusher target size (bytes)
	FlushMaxRows int    // flusher max rows per file
	EventsDir    string // events subdirectory
}

// Router distributes writes across shards by consistent hash and fans out reads.
type Router struct {
	cfg    Config
	shards []*Instance
}

// New creates a shard router and initializes all shards.
func New(cfg Config) (*Router, error) {
	if cfg.NumShards < 1 {
		cfg.NumShards = 1
	}
	if cfg.BaseDir == "" {
		return nil, fmt.Errorf("shard: BaseDir required")
	}
	if cfg.EventsDir == "" {
		cfg.EventsDir = "events"
	}
	if cfg.FlushSize <= 0 {
		cfg.FlushSize = 256 << 20 // 256MB
	}
	if cfg.FlushMaxRows <= 0 {
		cfg.FlushMaxRows = 100000
	}

	r := &Router{cfg: cfg}

	for i := 0; i < cfg.NumShards; i++ {
		shardDir := filepath.Join(cfg.BaseDir, fmt.Sprintf("shard-%d", i))
		os.MkdirAll(shardDir, 0700)

		hot, err := sqlite.NewSQLiteHotStore(filepath.Join(shardDir, "hot.db"))
		if err != nil {
			return nil, fmt.Errorf("shard %d hot store: %w", i, err)
		}

		m, err := manifestpkg.NewManifest(filepath.Join(shardDir, "manifest.db"))
		if err != nil {
			hot.Close()
			return nil, fmt.Errorf("shard %d manifest: %w", i, err)
		}

		pwDir := filepath.Join(shardDir, "parquet-temp")
		os.MkdirAll(pwDir, 0700)
		pw := parquet.NewParquetWriter(pwDir, filepath.Join(shardDir, cfg.EventsDir), parquet.DefaultParquetOptions())

		f := flusher.NewFlusher(hot, m, pw, 0, int64(cfg.FlushSize), cfg.FlushMaxRows, filepath.Join(shardDir, cfg.EventsDir))

		cr := cold.NewDefaultReader()
		rou := router.NewRouter(hot, cr, m)

		r.shards = append(r.shards, &Instance{
			ID:       i,
			Dir:      shardDir,
			Hot:      hot,
			Manifest: m,
			Parquet:  pw,
			Flusher:  f,
			Router:   rou,
			Reader:   cr,
		})
	}

	return r, nil
}

// Close shuts down all shards.
func (r *Router) Close() {
	for _, s := range r.shards {
		s.Parquet.Close()
		s.Manifest.Close()
		s.Hot.Close()
	}
}

// ShardFor returns the shard index for a given tenant + agent.
func (r *Router) ShardFor(tenantID, agentID string) int {
	h := fnv.New64a()
	h.Write([]byte(tenantID + ":" + agentID))
	return int(h.Sum64() % uint64(len(r.shards)))
}

// WriteEvents routes each event to its shard and writes in batches.
func (r *Router) WriteEvents(ctx context.Context, events []*storage.Event) error {
	if len(events) == 0 {
		return nil
	}
	if len(r.shards) == 1 {
		return r.shards[0].Hot.WriteBatch(ctx, events)
	}

	// Group events by shard
	type batch struct {
		shard  int
		events []*storage.Event
	}
	shardBatches := make(map[int][]*storage.Event)
	for _, e := range events {
		s := r.ShardFor(e.TenantID, e.AgentID)
		shardBatches[s] = append(shardBatches[s], e)
	}

	// Write to each shard concurrently
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for s, batchEvents := range shardBatches {
		wg.Add(1)
		go func(sIdx int, evts []*storage.Event) {
			defer wg.Done()
			if err := r.shards[sIdx].Hot.WriteBatch(ctx, evts); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(s, batchEvents)
	}
	wg.Wait()
	return firstErr
}

// Query fans out to all shards and merges results.
func (r *Router) Query(ctx context.Context, q storage.Query) (*storage.Result, error) {
	if len(r.shards) == 1 {
		return r.shards[0].Router.Query(ctx, q)
	}

	type partial struct {
		res *storage.Result
		err error
	}
	ch := make(chan partial, len(r.shards))

	for _, s := range r.shards {
		go func(sh *Instance) {
			res, err := sh.Router.Query(ctx, q)
			ch <- partial{res, err}
		}(s)
	}

	var allEvents []*storage.Event
	var warnings []string
	for i := 0; i < len(r.shards); i++ {
		p := <-ch
		if p.err != nil {
			warnings = append(warnings, fmt.Sprintf("shard %d: %v", i, p.err))
			continue
		}
		if p.res != nil {
			allEvents = append(allEvents, p.res.Events...)
			warnings = append(warnings, p.res.Warnings...)
		}
	}

	// Sort by time (UUIDv7 order) and dedup
	allEvents = mergeSortDedupByID(allEvents)

	// Apply limit
	if q.Limit > 0 && len(allEvents) > q.Limit {
		allEvents = allEvents[:q.Limit]
	}

	result := &storage.Result{
		Events:   allEvents,
		Warnings: warnings,
	}
	if len(allEvents) > 0 {
		result.Cursor = allEvents[len(allEvents)-1].ID
	}
	return result, nil
}

// NumShards returns the number of configured shards.
func (r *Router) NumShards() int { return len(r.shards) }

// Instances returns all shard instances (for lifecycle management).
func (r *Router) Instances() []*Instance { return r.shards }

func mergeSortDedupByID(events []*storage.Event) []*storage.Event {
	if len(events) < 2 {
		return events
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].ID < events[j].ID
	})
	deduped := events[:1]
	for i := 1; i < len(events); i++ {
		if events[i].ID != events[i-1].ID {
			deduped = append(deduped, events[i])
		}
	}
	return deduped
}

// ShardCount returns the configured number of shards.
func (r *Router) ShardCount() int { return len(r.shards) }

// ID returns a human-readable identifier.
func (r *Router) ID() string {
	return fmt.Sprintf("shard-router(%d shards)", len(r.shards))
}
