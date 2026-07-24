package gc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
)

func TestNewGC(t *testing.T) {
	m, _ := manifestpkg.NewManifest(filepath.Join(t.TempDir(), "manifest.db"))
	defer m.Close()

	g := NewGC(m, 0)
	if g == nil {
		t.Fatal("expected non-nil GC")
	}
	if g.interval != 24*time.Hour {
		t.Errorf("expected default interval 24h, got %v", g.interval)
	}
}

func TestGC_RunCancel(t *testing.T) {
	m, _ := manifestpkg.NewManifest(filepath.Join(t.TempDir(), "manifest.db"))
	defer m.Close()

	g := NewGC(m, 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := g.Run(ctx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestGC_CollectOnce_DeletesExpired(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	m, _ := manifestpkg.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()

	g := NewGC(m, 0)
	g.grace = 10 * time.Millisecond

	// Create an expired file
	oldPath := filepath.Join(dir, "old.parquet")
	os.WriteFile(oldPath, []byte("data"), 0644)

	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "expired-file",
		Path:           oldPath,
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: 1,
		MaxTimestampUs: 1,
		MinEventID:     "a",
		MaxEventID:     "b",
		SHA256:         "sha",
	})
	m.UpdateFileStatus(ctx, "expired-file", "expired")

	time.Sleep(20 * time.Millisecond)

	g.collectOnce(ctx)

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("expected expired file to be deleted")
	}

	files, _ := m.FilesFor(ctx, "", 0, 0, "deleted")
	if len(files) != 1 {
		t.Errorf("expected 1 file marked deleted, got %d", len(files))
	}
}

func TestGC_CollectOnce_KeepsWithinGrace(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	m, _ := manifestpkg.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()

	g := NewGC(m, 0)
	g.grace = 1 * time.Hour

	recentPath := filepath.Join(dir, "recent.parquet")
	os.WriteFile(recentPath, []byte("data"), 0644)

	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "recent-file",
		Path:           recentPath,
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: time.Now().UnixMicro(),
		MaxTimestampUs: time.Now().UnixMicro(),
		MinEventID:     "a",
		MaxEventID:     "b",
		SHA256:         "sha",
	})
	m.UpdateFileStatus(ctx, "recent-file", "expired")

	g.collectOnce(ctx)

	if _, err := os.Stat(recentPath); os.IsNotExist(err) {
		t.Error("expected recent file to remain within grace period")
	}

	files, _ := m.FilesFor(ctx, "", 0, 0, "expired")
	if len(files) != 1 {
		t.Errorf("expected 1 file still expired, got %d", len(files))
	}
}

func TestGC_CollectOnce_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	m, _ := manifestpkg.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()

	g := NewGC(m, 0)
	g.grace = 10 * time.Millisecond

	// Register a file that doesn't exist on disk
	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "missing-file",
		Path:           filepath.Join(dir, "nonexistent.parquet"),
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: 1,
		MaxTimestampUs: 1,
		MinEventID:     "a",
		MaxEventID:     "b",
		SHA256:         "sha",
	})
	m.UpdateFileStatus(ctx, "missing-file", "expired")

	time.Sleep(20 * time.Millisecond)

	g.collectOnce(ctx)

	// Should be marked deleted even though file didn't exist
	files, _ := m.FilesFor(ctx, "", 0, 0, "deleted")
	if len(files) != 1 {
		t.Errorf("expected 1 file marked deleted despite missing on disk, got %d", len(files))
	}
}
