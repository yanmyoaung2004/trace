package harness

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/router"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

func TestPipeline_WriteFlushRouter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full pipeline test in short mode")
	}

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Init all components
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer hot.Close()

	m, err := manifestpkg.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "events"),
		parquet.DefaultParquetOptions(),
	)
	defer pw.Close()

	f := flusher.NewFlusher(hot, m, pw, 3*time.Second, 10*1000, 10000, filepath.Join(dir, "events"))
	go f.Run(ctx)
	time.Sleep(500 * time.Millisecond)

	cr := cold.NewParquetReader()
	r := router.NewRouter(hot, cr, m)

	// 2. Write events
	now := time.Now()
	events := make([]*storage.Event, 100)
	for i := 0; i < 100; i++ {
		events[i] = &storage.Event{
			ID:        id(i),
			TenantID:  "integration",
			AgentID:   "agent",
			Timestamp: now.UnixMicro() + int64(i),
			EventType: "test",
			Severity:  1,
		}
	}

	if err := hot.WriteBatch(ctx, events); err != nil {
		t.Fatal(err)
	}

	// 3. Verify hot store
	hotResult, err := hot.Query(ctx, storage.Query{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(hotResult.Events) != 100 {
		t.Fatalf("hot store: expected 100 events, got %d", len(hotResult.Events))
	}

	// 4. Wait for flush
	time.Sleep(5 * time.Second)

	// 5. Verify watermark advanced
	wm, err := m.Watermark(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wm.LastID == "" {
		t.Fatal("watermark was not advanced after flush")
	}

	// 6. Router query (hot+cold)
	result, err := r.Query(ctx, storage.Query{Limit: 100, MinSeverity: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 100 {
		t.Fatalf("router: expected 100 events, got %d", len(result.Events))
	}
}

func TestPipeline_EmptyPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full pipeline test in short mode")
	}

	dir := t.TempDir()
	ctx := context.Background()

	hot, _ := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	defer hot.Close()
	m, _ := manifestpkg.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()
	pw := parquet.NewParquetWriter(dir, dir, parquet.DefaultParquetOptions())
	defer pw.Close()
	cr := cold.NewParquetReader()
	r := router.NewRouter(hot, cr, m)

	result, err := r.Query(ctx, storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events from empty pipeline, got %d", len(result.Events))
	}
}

func id(i int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
}
