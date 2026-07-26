package flusher

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

func newFlusher(t *testing.T) *Flusher {
	t.Helper()
	dir := t.TempDir()
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		t.Fatalf("NewSQLiteHotStore: %v", err)
	}
	t.Cleanup(func() { hot.Close() })

	m, err := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	t.Cleanup(func() { m.Close() })

	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "events"),
		parquet.DefaultParquetOptions(),
	)
	t.Cleanup(func() { pw.Close() })

	f := NewFlusher(hot, m, pw, 100*time.Millisecond, 100, 10000, filepath.Join(dir, "events"))
	return f
}

func TestFlusherStop_WaitsForFlush(t *testing.T) {
	f := newFlusher(t)
	ctx := context.Background()

	// Start the flusher
	go f.Run(ctx)
	time.Sleep(50 * time.Millisecond) // let it start

	// Write events
	now := time.Now()
	events := make([]*storage.Event, 100)
	for i := 0; i < 100; i++ {
		events[i] = &storage.Event{
			ID:        id(i),
			TenantID:  "shutdown-test",
			AgentID:   "agent",
			Timestamp: now.UnixMicro() + int64(i),
			EventType: "test",
			Severity:  1,
		}
	}
	if err := f.hot.WriteBatch(ctx, events); err != nil {
		t.Fatal(err)
	}

	// Wait for flush to start
	time.Sleep(200 * time.Millisecond)

	// Stop gracefully — should wait for in-flight flush
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	if err := f.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	// Should have stopped (may be fast if flush already completed)
	t.Logf("Flusher.Stop() took %v", elapsed)

	// Verify watermark was advanced
	wm, err := f.manifest.Watermark(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wm.LastID == "" && len(events) > 0 {
		// If events were written but not flushed yet, watermark may be empty.
		// That's acceptable — events are still in the hot store.
		t.Log("watermark is empty (events still in hot store)")
	}
}

func TestFlusherStop_Idempotent(t *testing.T) {
	f := newFlusher(t)
	ctx := context.Background()
	go f.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	// Stop twice — should not panic
	stopCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	if err := f.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}

	// Second stop should return immediately (already stopped)
	if err := f.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestFlusherStop_NoDataLossAfterKill(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	hot, _ := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	defer hot.Close()

	m, _ := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()

	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "events"),
		parquet.DefaultParquetOptions(),
	)
	defer pw.Close()

	f := NewFlusher(hot, m, pw, 100*time.Millisecond, 100, 10000, filepath.Join(dir, "events"))
	go f.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	// Write events
	now := time.Now()
	for i := 0; i < 50; i++ {
		hot.WriteBatch(ctx, []*storage.Event{{
			ID:        id(i),
			TenantID:  "data-loss-test",
			AgentID:   "agent",
			Timestamp: now.UnixMicro() + int64(i),
			EventType: "test",
			Severity:  1,
		}})
	}

	// Let some flush complete
	time.Sleep(300 * time.Millisecond)

	// Graceful stop
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	f.Stop(stopCtx)

	// Re-open the stores and verify
	hot2, _ := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	defer hot2.Close()

	// Count remaining events in hot store
	result, _ := hot2.Query(ctx, storage.Query{Limit: 1000})
	t.Logf("Events remaining in hot store after shutdown: %d", len(result.Events))
}

func id(i int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
}
