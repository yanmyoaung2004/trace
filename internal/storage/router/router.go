package router

import (
	"container/heap"
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// Router transparently routes queries to the hot tier (SQLite) and cold tier
// (Parquet via ColdReader), merging results with deduplication by UUIDv7.
//
// The cutoff is the live watermark from the manifest, not a wall-clock value.
// A 10-minute overlap window prevents boundary race conditions.
type Router struct {
	hot      *sqlite.SQLiteHotStore
	cold     cold.ColdReader
	manifest *manifest.Manifest

	// wmCache caches the watermark + FilesFor results for a short TTL (D12),
	// invalidated on flush/compact via InvalidateCache. The mutex guards the
	// cache only; query fan-out below uses per-tier limits + a single k-way
	// merge (P-R1) instead of materialize-then-limit.
	mu       sync.Mutex
	wmCached *storage.Watermark
	wmAt     time.Time
	filesCache map[string]cachedFiles
}

// filesCacheTTL bounds manifest re-reads per query burst (D12).
const filesCacheTTL = 5 * time.Second

// cachedFiles holds a TTL-guarded FilesFor result.
type cachedFiles struct {
	files []storage.FileInfo
	at    time.Time
}

// NewRouter creates a hot/cold query router.
func NewRouter(hot *sqlite.SQLiteHotStore, cr cold.ColdReader, m *manifest.Manifest) *Router {
	return &Router{hot: hot, cold: cr, manifest: m, filesCache: make(map[string]cachedFiles)}
}

// InvalidateCache drops the watermark/FilesFor TTL cache (call after flush/compact).
func (r *Router) InvalidateCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wmCached = nil
	r.filesCache = make(map[string]cachedFiles)
}

// cachedWatermark returns the watermark, reusing the TTL cache when fresh.
func (r *Router) cachedWatermark(ctx context.Context) (*storage.Watermark, error) {
	r.mu.Lock()
	if r.wmCached != nil && time.Since(r.wmAt) < filesCacheTTL {
		wm := *r.wmCached
		r.mu.Unlock()
		return &wm, nil
	}
	r.mu.Unlock()
	wm, err := r.manifest.Watermark(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	cp := *wm
	r.wmCached = &cp
	r.wmAt = time.Now()
	r.mu.Unlock()
	return wm, nil
}

// cachedFilesFor returns FilesFor, reusing the TTL cache when fresh.
func (r *Router) cachedFilesFor(ctx context.Context, tenantID string, sinceUs, untilUs int64, status string) ([]storage.FileInfo, error) {
	key := fmt.Sprintf("%s|%d|%d|%s", tenantID, sinceUs, untilUs, status)
	r.mu.Lock()
	if c, ok := r.filesCache[key]; ok && time.Since(c.at) < filesCacheTTL {
		out := make([]storage.FileInfo, len(c.files))
		copy(out, c.files)
		r.mu.Unlock()
		return out, nil
	}
	r.mu.Unlock()
	files, err := r.manifest.FilesFor(ctx, tenantID, sinceUs, untilUs, status)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.filesCache[key] = cachedFiles{files: files, at: time.Now()}
	r.mu.Unlock()
	return files, nil
}

// Query executes a query across both hot and cold tiers, merging results.
// Per-tier limits are pushed down (P-R1); the merge is a single k-way merge
// over ID-sorted cursors with dedup instead of materialize-then-limit.
func (r *Router) Query(ctx context.Context, q storage.Query) (*storage.Result, error) {
	start := time.Now()
	q = q.ApplyDefaults()
	wm, err := r.cachedWatermark(ctx)
	if err != nil {
		return nil, fmt.Errorf("watermark: %w", err)
	}

	boundary := wm.LastTS
	overlap := int64(10 * time.Minute) // 10-min overlap in microseconds

	var (
		result   storage.Result
		mu       sync.Mutex
		hadError atomic.Bool
	)

	// Per-tier pushdown: each tier returns at most Limit rows.
	hotQ, coldQ := q, q

	// Determine if we need hot and/or cold queries
	needHot := q.SinceUs == 0 || q.UntilUs == 0 || q.UntilUs > boundary-overlap
	needCold := q.UntilUs == 0 || q.SinceUs < boundary+overlap

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	var hotEvents, coldEvents []*storage.Event

	// Hot query (SQLite): data newer than watermark - overlap
	if needHot {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if hotQ.SinceUs == 0 || hotQ.SinceUs < boundary-overlap {
				hotQ.SinceUs = boundary - overlap
			}

			hotResult, err := r.hot.Query(ctx, hotQ)
			if err != nil {
				errs <- fmt.Errorf("hot query: %w", err)
				hadError.Store(true)
				return
			}

			mu.Lock()
			hotEvents = hotResult.Events
			result.Warnings = append(result.Warnings, hotResult.Warnings...)
			mu.Unlock()
		}()
	}

	// Cold query (Parquet via ColdReader): data older than watermark + overlap
	if needCold {
		wg.Add(1)
		go func() {
			defer wg.Done()

			files, err := r.cachedFilesFor(ctx, q.TenantID, q.SinceUs, q.UntilUs, "committed")
			if err != nil {
				errs <- fmt.Errorf("manifest lookup: %w", err)
				hadError.Store(true)
				return
			}

			if len(files) == 0 {
				return
			}

			if coldQ.UntilUs == 0 || coldQ.UntilUs > boundary+overlap {
				coldQ.UntilUs = boundary + overlap
			}

			coldResult, err := r.cold.QueryFiles(ctx, files, coldQ)
			if err != nil {
				// Cold tier failure is non-fatal — return partial results with warning
				mu.Lock()
				result.Warnings = append(result.Warnings, fmt.Sprintf("cold tier: %v", err))
				mu.Unlock()
				return
			}

			mu.Lock()
			coldEvents = coldResult.Events
			result.Warnings = append(result.Warnings, coldResult.Warnings...)
			mu.Unlock()
		}()
	}

	wg.Wait()
	close(errs)

	// Collect errors (non-fatal in most cases)
	for e := range errs {
		result.Warnings = append(result.Warnings, e.Error())
	}

	// Single k-way merge over ID-sorted cursors (P-R1): both tiers return
	// ID-ordered rows, so merge in one pass with dedup + limit.
	result.Events = kWayMergeDedup(hotEvents, coldEvents, q.Limit)

	// Cursor
	if len(result.Events) > 0 {
		result.Cursor = result.Events[len(result.Events)-1].ID
	}

	result.Total = len(result.Events)

	elapsed := time.Since(start)
	metrics.Global.EventsRead.Add(int64(len(result.Events)))
	if hadError.Load() {
		metrics.Global.QueryErrors.Add(1)
		log.Printf("[tse] query errors=%d events=%d took=%v", len(result.Warnings), len(result.Events), elapsed.Round(time.Millisecond))
	}

	return &result, nil
}

// kWayMergeDedup merges ID-sorted tier slices in one pass with dedup by ID
// and an output cap (limit<=0 = uncapped). Inputs may be unsorted (defensive
// sort per tier keeps the merge correct without a global re-sort of 2N rows).
func kWayMergeDedup(a, b []*storage.Event, limit int) []*storage.Event {
	if len(a) > 1 {
		sort.Slice(a, func(i, j int) bool { return a[i].ID < a[j].ID })
	}
	if len(b) > 1 {
		sort.Slice(b, func(i, j int) bool { return b[i].ID < b[j].ID })
	}
	h := &eventHeap{}
	heap.Init(h)
	if len(a) > 0 {
		heap.Push(h, &eventCursor{events: a})
	}
	if len(b) > 0 {
		heap.Push(h, &eventCursor{events: b})
	}
	var out []*storage.Event
	var lastID string
	for h.Len() > 0 {
		if limit > 0 && len(out) >= limit {
			break
		}
		c := heap.Pop(h).(*eventCursor)
		e := c.events[c.idx]
		c.idx++
		if c.idx < len(c.events) {
			heap.Push(h, c)
		}
		if e.ID == lastID {
			continue
		}
		lastID = e.ID
		out = append(out, e)
	}
	return out
}

// eventCursor iterates one ID-sorted tier inside the merge heap.
type eventCursor struct {
	events []*storage.Event
	idx    int
}

// eventHeap orders cursors by current head ID.
type eventHeap []*eventCursor

// Len implements heap.Interface.
func (h eventHeap) Len() int { return len(h) }

// Less implements heap.Interface.
func (h eventHeap) Less(i, j int) bool { return h[i].events[h[i].idx].ID < h[j].events[h[j].idx].ID }

// Swap implements heap.Interface.
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

// Push implements heap.Interface.
func (h *eventHeap) Push(x any) { *h = append(*h, x.(*eventCursor)) }

// Pop implements heap.Interface.
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	c := old[n-1]
	*h = old[:n-1]
	return c
}
