package admin

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
)

func newTestManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	dir := t.TempDir()
	m, err := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestStatus_Empty(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	// Setup some metrics
	metrics.Global.EventsEnqueued.Store(100)
	metrics.Global.EventsFlushed.Store(80)
	metrics.Global.HotTableCount.Store(3)
	metrics.Global.ColdFileCount.Store(5)
	defer metrics.Global.EventsEnqueued.Store(0)
	defer metrics.Global.EventsFlushed.Store(0)
	defer metrics.Global.HotTableCount.Store(0)
	defer metrics.Global.ColdFileCount.Store(0)

	s, err := Status(ctx, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Fatal("expected non-empty status")
	}
}

func TestStatus_WithWatermark(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	m.UpdateWatermark(ctx, "wm-001", time.Now().UnixMicro())

	s, err := Status(ctx, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Fatal("expected non-empty status")
	}
}

func TestInspect_Empty(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	s, err := Inspect(ctx, m, 10)
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Error("expected non-empty output even when empty")
	}
}

func TestInspect_WithFiles(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := m.AddFile(ctx, storage.ParquetFileRecord{
			FileID:     fmt.Sprintf("f-%d", i),
			Path:       fmt.Sprintf("/data/file-%d.parquet", i),
			TenantID:   "test",
			Level:      0,
			MinTimestampUs: int64(i * 1000),
			MaxTimestampUs: int64((i + 1) * 1000),
			MinEventID: "a",
			MaxEventID: "b",
			SHA256:     "sha",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	s, err := Inspect(ctx, m, 10)
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Error("expected non-empty output")
	}
}

func TestInspect_WithLimit(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		m.AddFile(ctx, storage.ParquetFileRecord{
			FileID:     fmt.Sprintf("f-%d", i),
			Path:       fmt.Sprintf("/data/file-%d.parquet", i),
			TenantID:   "test",
			Level:      0,
			MinTimestampUs: int64(i * 1000),
			MaxTimestampUs: int64((i + 1) * 1000),
			MinEventID: "a",
			MaxEventID: "b",
			SHA256:     "sha",
		})
	}

	s, err := Inspect(ctx, m, 3)
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Error("expected non-empty output with limit")
	}
}
