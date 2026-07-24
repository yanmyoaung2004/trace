package manifest

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func newTestManifest(t *testing.T) *Manifest {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.db")
	m, err := NewManifest(path)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func testFileRecord() storage.ParquetFileRecord {
	now := time.Now().UnixMicro()
	return storage.ParquetFileRecord{
		FileID:           "file-1",
		Path:             "/data/events/test/2026/07/24/part-0001.parquet",
		TenantID:         "test-tenant",
		Level:            0,
		MinTimestampUs:   now - 3600_000_000,
		MaxTimestampUs:   now,
		MinEventID:       "00000000-0000-0000-0000-000000000001",
		MaxEventID:       "00000000-0000-0000-0000-000000000010",
		RowCount:         1000,
		CompressedSize:   1024,
		UncompressedSize: 10240,
		SHA256:           "abc123def456",
		Compression:      "zstd",
		SchemaVersion:    1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func TestManifest_New(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	wm, err := m.Watermark(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wm.LastID != "" {
		t.Errorf("expected empty initial watermark, got %s", wm.LastID)
	}
}

func TestManifest_AddFile(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	file := testFileRecord()
	if err := m.AddFile(ctx, file); err != nil {
		t.Fatal(err)
	}
}

func TestManifest_Watermark(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	// Update watermark
	if err := m.UpdateWatermark(ctx, "wm-001", 1000); err != nil {
		t.Fatal(err)
	}

	wm, err := m.Watermark(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wm.LastID != "wm-001" {
		t.Errorf("expected wm-001, got %s", wm.LastID)
	}
	if wm.LastTS != 1000 {
		t.Errorf("expected 1000, got %d", wm.LastTS)
	}
}

func TestManifest_FilesFor(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	m.AddFile(ctx, testFileRecord())

	files, err := m.FilesFor(ctx, "test-tenant", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
	if files[0].FileID != "file-1" {
		t.Errorf("expected file-1, got %s", files[0].FileID)
	}
}

func TestManifest_FilesFor_NoMatch(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	m.AddFile(ctx, testFileRecord())

	files, err := m.FilesFor(ctx, "other-tenant", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files for other tenant, got %d", len(files))
	}
}

func TestManifest_Transaction(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	// Execute an atomic transaction
	err := m.Transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO parquet_files (file_id, path, tenant_id, level,
				min_ts_us, max_ts_us, min_event_id, max_event_id,
				row_count, compressed_size, uncompressed_size,
				sha256, compression, schema_version, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'committed', ?, ?)
		`,
			"tx-file-1", "/path/to/file.parquet", "tx-tenant",
			0, 100, 200, "id-1", "id-2",
			500, 512, 5120, "sha", "zstd",
			time.Now().UnixMicro(), time.Now().UnixMicro(),
		)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	files, err := m.FilesFor(ctx, "tx-tenant", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file from tx, got %d", len(files))
	}
}

func TestManifest_HotTableLifecycle(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	if err := m.RegisterHotTable(ctx, "edr_events_2026072415", 1000); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkHotTableFlushed(ctx, "edr_events_2026072415"); err != nil {
		t.Fatal(err)
	}
	if err := m.DropHotTable(ctx, "edr_events_2026072415"); err != nil {
		t.Fatal(err)
	}
}

func TestManifest_UpdateFileStatus(t *testing.T) {
	m := newTestManifest(t)
	ctx := context.Background()

	m.AddFile(ctx, testFileRecord())

	if err := m.UpdateFileStatus(ctx, "file-1", "corrupted"); err != nil {
		t.Fatal(err)
	}

	files, err := m.FilesFor(ctx, "test-tenant", 0, 0, "corrupted")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 corrupted file, got %d", len(files))
	}
}

func TestOrphanGC(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	m, err := NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Create an orphan Parquet file
	orphanPath := filepath.Join(dir, "orphan.parquet")
	if err := os.WriteFile(orphanPath, []byte("not a real parquet"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a committed file
	committedPath := filepath.Join(dir, "committed.parquet")
	if err := os.WriteFile(committedPath, []byte("also fake"), 0644); err != nil {
		t.Fatal(err)
	}
	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID: "committed-file",
		Path:   committedPath,
		TenantID: "test",
		MinTimestampUs: 1,
		MaxTimestampUs: 2,
		MinEventID: "a",
		MaxEventID: "b",
		SHA256: "sha",
	})

	// Run orphan GC
	if err := OrphanGC(ctx, dir, m); err != nil {
		t.Fatal(err)
	}

	// Orphan should be deleted
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Errorf("expected orphan to be deleted: %v", err)
	}

	// Committed should remain
	if _, err := os.Stat(committedPath); os.IsNotExist(err) {
		t.Errorf("expected committed file to remain")
	}
}
