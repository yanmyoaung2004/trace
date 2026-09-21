package flusher

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// Flusher moves data from the hot tier (SQLite) to the cold tier (Parquet)
// behind a watermark cursor. It implements the exactly-once semantics
// described in the TSE architecture.
//
// The watermark is the single source of truth for what has been committed.
// If the process crashes mid-flush, the watermark is not advanced, and the
// flusher re-reads the same rows from SQLite on restart. No duplicates,
// no data loss.
type Flusher struct {
	mu       sync.Mutex
	hot      *sqlite.SQLiteHotStore
	manifest *manifest.Manifest
	parquet  *parquet.ParquetWriter

	interval    time.Duration
	targetSize  int64
	batchLimit  int
	outputDir   string

	// alerting state
	errCount    int
	errWindow   time.Time

	// AlertFunc is called when alert threshold is exceeded.
	AlertFunc func(message string)

	// shutdown signaling
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
}

// NewFlusher creates a watermark-driven flusher.
func NewFlusher(
	hot *sqlite.SQLiteHotStore,
	m *manifest.Manifest,
	pw *parquet.ParquetWriter,
	interval time.Duration,
	targetSize int64,
	batchLimit int,
	outputDir string,
) *Flusher {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if targetSize <= 0 {
		targetSize = 256 << 20 // 256MB
	}
	if batchLimit <= 0 {
		batchLimit = 100000
	}
	return &Flusher{
		hot:        hot,
		manifest:   m,
		parquet:    pw,
		interval:   interval,
		targetSize: targetSize,
		batchLimit: batchLimit,
		outputDir:  outputDir,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

// Run starts the flusher loop. It blocks until the context is cancelled.
func (f *Flusher) Run(ctx context.Context) error {
	log.Printf("[flusher] started (interval=%v, target=%dMB)", f.interval, f.targetSize>>20)
	defer close(f.doneCh)

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.stopCh:
			return nil
		case <-ticker.C:
			if err := f.flush(ctx); err != nil {
				metrics.Global.FlushErrors.Add(1)
				log.Printf("[tse] flush error: %v", err)
				f.trackError(ctx)
			}
		}
	}
}

// Stop signals the flusher to stop after the current flush completes.
// It blocks until the Run loop exits or the context is cancelled.
// Idempotent — safe to call multiple times.
func (f *Flusher) Stop(ctx context.Context) error {
	f.stopOnce.Do(func() {
		close(f.stopCh)
	})
	select {
	case <-f.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FlushNow triggers an immediate flush cycle.
func (f *Flusher) FlushNow(ctx context.Context) error {
	return f.flush(ctx)
}

// Watermark returns the current high-water mark from the manifest.
func (f *Flusher) Watermark(ctx context.Context) (*storage.Watermark, error) {
	return f.manifest.Watermark(ctx)
}

// flush executes one flush cycle:
//  1. Read watermark
//  2. Read events from SQLite hot tables (id > watermark)
//  3. Group by (tenant_id, hour_of_timestamp)
//  4. For each ready group: sort, write Parquet, commit manifest
//  5. Advance watermark only past contiguously flushed ranges (R3); per-group
//     watermark commits are replaced by one commit covering the contiguous
//     prefix of the sorted batch. FileIDs are deterministic
//     (tenant/hour/minTS-maxTS) so a retry reuses the same identity instead of
//     minting duplicate files (R3).
func (f *Flusher) flush(ctx context.Context) error {
	start := time.Now()
	// 1. Read watermark (no lock needed for read).
	wm, err := f.manifest.Watermark(ctx)
	if err != nil {
		return fmt.Errorf("watermark: %w", err)
	}

	// 2. Read events from SQLite
	result, err := f.hot.Query(ctx, storage.Query{
		MinID:   wm.LastID,
		Limit:   f.batchLimit,
		OrderAsc: true,
	})
	if err != nil {
		return fmt.Errorf("query hot: %w", err)
	}
	if len(result.Events) == 0 {
		return nil // nothing to flush
	}

	// 3. Group by (tenant_id, hour)
	groups := groupEvents(result.Events)

	// 4. Process ready groups (prepare Parquet files without holding f.mu;
	// only the manifest commit takes the lock — narrow scope, P-H7).
	ready := readyGroups(groups, f.targetSize)
	type committed struct {
		key        groupKey
		fileRecord storage.ParquetFileRecord
		maxID      string
		maxTS      int64
		minID      string
	}
	var done []committed
	for _, key := range ready {
		group := groups[key]
		sort.Slice(group, func(i, j int) bool {
			if group[i].AgentID != group[j].AgentID {
				return group[i].AgentID < group[j].AgentID
			}
			return group[i].Timestamp < group[j].Timestamp
		})

		// Build partition key
		t := time.UnixMicro(key.Hour)
		partitionKey := fmt.Sprintf("%s/%s/%s", key.TenantID, t.Format("2006-01-02"), t.Format("15"))

		// Write Parquet file
		fileResult, err := f.parquet.WriteBatch(ctx, group, partitionKey)
		if err != nil {
			return fmt.Errorf("write parquet: %w", err)
		}

		now := time.Now().UnixMicro()
		fileRecord := storage.ParquetFileRecord{
			FileID:           deterministicFileID(key.TenantID, key.Hour, fileResult.MinTimestampUs, fileResult.MaxTimestampUs, fileResult.MinEventID, fileResult.MaxEventID),
			Path:             fileResult.Path,
			TenantID:         key.TenantID,
			Level:            0,
			MinTimestampUs:   fileResult.MinTimestampUs,
			MaxTimestampUs:   fileResult.MaxTimestampUs,
			MinEventID:       fileResult.MinEventID,
			MaxEventID:       fileResult.MaxEventID,
			RowCount:         fileResult.RowCount,
			CompressedSize:   fileResult.CompressedSize,
			UncompressedSize: fileResult.UncompressedSize,
			SHA256:           fileResult.SHA256,
			Compression:      "zstd",
			SchemaVersion:    1,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		done = append(done, committed{key: key, fileRecord: fileRecord, maxID: fileResult.MaxEventID, maxTS: fileResult.MaxTimestampUs, minID: fileResult.MinEventID})

		log.Printf("[tse] flush committed %s events=%d size=%s ids=%s..%s took=%v",
			partitionKey, fileResult.RowCount, formatSize(fileResult.CompressedSize),
			fileResult.MinEventID[:8], fileResult.MaxEventID[:8], time.Since(start).Round(time.Millisecond))
	}

	if len(done) == 0 {
		return nil
	}

	// 5. Commit to manifest in a single transaction; advance the watermark
	// only past the contiguous ID prefix of this batch (R3: no gaps).
	f.mu.Lock()
	defer f.mu.Unlock()
	curWM, err := f.manifest.Watermark(ctx)
	if err != nil {
		return fmt.Errorf("watermark re-read: %w", err)
	}
	_ = curWM
	// Sort committed groups by min ID so contiguity is well-defined.
	sort.Slice(done, func(i, j int) bool { return done[i].minID < done[j].minID })
	contig := done
	// The batch was read as id > watermark ordered by id; groups flushed are a
	// subset (ready only). Advance to the max ID only if every event up to it
	// was flushed: check that no unflushed (unready) event sorts below it.
	unreadyMax := ""
	for key, events := range groups {
		readyKey := false
		for _, r := range ready {
			if r == key {
				readyKey = true
				break
			}
		}
		if readyKey {
			continue
		}
		for _, e := range events {
			if e.ID > unreadyMax {
				unreadyMax = e.ID
			}
		}
	}
	advanceTo := -1
	for i, d := range contig {
		if unreadyMax != "" && unreadyMax < d.maxID {
			// An unready event sorts below this group's max: stop here.
			break
		}
		advanceTo = i
	}
	if err := f.manifest.Transaction(ctx, func(tx *sql.Tx) error {
		for _, d := range done {
			// Idempotent retry: deterministic FileID means re-insert may hit
			// the PK; treat as already-committed.
			if err := f.manifest.AddFileTx(ctx, tx, d.fileRecord); err != nil {
				if !isPKConflict(err) {
					return fmt.Errorf("add file: %w", err)
				}
			}
		}
		if advanceTo >= 0 {
			top := contig[advanceTo]
			if err := f.manifest.UpdateWatermarkTx(ctx, tx, top.maxID, top.maxTS); err != nil {
				return fmt.Errorf("update watermark: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("manifest tx: %w", err)
	}

	return nil
}

// deterministicFileID derives a stable FileID from (tenant, hour, min/max TS,
// min/max event ID) so flush retries reuse the same identity (R3).
func deterministicFileID(tenant string, hour, minTS, maxTS int64, minID, maxID string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%d|%s|%s", tenant, hour, minTS, maxTS, minID, maxID)))
	return hex.EncodeToString(h[:])[:32]
}

// isPKConflict reports SQLite primary-key/unique conflicts for idempotent retry.
func isPKConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint") || strings.Contains(msg, "PRIMARY KEY") || strings.Contains(msg, "constraint failed")
}

const alertErrorThreshold = 5

func (f *Flusher) trackError(ctx context.Context) {
	now := time.Now()
	if now.Sub(f.errWindow) > time.Minute {
		f.errCount = 0
		f.errWindow = now
	}
	f.errCount++
	if f.errCount >= alertErrorThreshold {
		msg := fmt.Sprintf("[tse] ALERT: flush errors exceeded threshold (%d in 1min)", f.errCount)
		log.Print(msg)
		if f.AlertFunc != nil {
			f.AlertFunc(msg)
		}
		f.errCount = 0
	}
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%dKB", bytes/1024)
	} else {
		return fmt.Sprintf("%dMB", bytes/(1024*1024))
	}
}
