package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
)

func TestCreateRestore_Roundtrip(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create a manifest and hot store in srcDir
	m, err := manifest.NewManifest(filepath.Join(srcDir, "manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	m.Close()

	// Create a placeholder hot.db
	if err := os.WriteFile(filepath.Join(srcDir, "hot.db"), []byte("hot data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a parquet event file to test recursive inclusion
	eventsDir := filepath.Join(srcDir, "events", "test", "2026", "07", "24")
	os.MkdirAll(eventsDir, 0700)
	if err := os.WriteFile(filepath.Join(eventsDir, "part-0001.parquet"), []byte("parquet data"), 0644); err != nil {
		t.Fatal(err)
	}

	snapshotPath := filepath.Join(t.TempDir(), "snapshot.tar.gz")

	// Create snapshot
	if err := Create(ctx, snapshotPath, srcDir, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Verify snapshot file exists
	if _, err := os.Stat(snapshotPath); os.IsNotExist(err) {
		t.Fatal("snapshot file was not created")
	}

	// Restore snapshot
	if err := Restore(ctx, snapshotPath, dstDir); err != nil {
		t.Fatal(err)
	}

	// Verify restored files
	checks := []struct {
		relPath  string
		exists   bool
	}{
		{"manifest.db", true},
		{"hot.db", true},
		{filepath.Join("events", "test", "2026", "07", "24", "part-0001.parquet"), true},
	}
	for _, c := range checks {
		fullPath := filepath.Join(dstDir, c.relPath)
		_, err := os.Stat(fullPath)
		if c.exists && os.IsNotExist(err) {
			t.Errorf("expected %s to exist after restore", c.relPath)
		}
		if !c.exists && err == nil {
			t.Errorf("expected %s to not exist after restore", c.relPath)
		}
	}
}

func TestCreate_EmptyDataDir(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	snapshotPath := filepath.Join(t.TempDir(), "snapshot.tar.gz")

	if err := Create(ctx, snapshotPath, srcDir, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Restore and verify
	dstDir := t.TempDir()
	if err := Restore(ctx, snapshotPath, dstDir); err != nil {
		t.Fatal(err)
	}
}

func TestCreate_MissingManifest(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	snapshotPath := filepath.Join(t.TempDir(), "snapshot.tar.gz")

	// Create hot.db but no manifest.db
	os.WriteFile(filepath.Join(srcDir, "hot.db"), []byte("data"), 0644)

	if err := Create(ctx, snapshotPath, srcDir, nil, nil); err != nil {
		t.Fatal(err)
	}

	dstDir := t.TempDir()
	if err := Restore(ctx, snapshotPath, dstDir); err != nil {
		t.Fatal(err)
	}

	// hot.db should exist, manifest.db should not
	if _, err := os.Stat(filepath.Join(dstDir, "hot.db")); os.IsNotExist(err) {
		t.Error("expected hot.db after restore")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "manifest.db")); err == nil {
		t.Error("expected manifest.db to not exist after restore (was missing in source)")
	}
}

func TestRestore_InvalidPath(t *testing.T) {
	ctx := context.Background()
	err := Restore(ctx, "/nonexistent/snapshot.tar.gz", t.TempDir())
	if err == nil {
		t.Fatal("expected error for nonexistent snapshot")
	}
}

func TestCreate_WithParquetFiles(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()

	// Create nested parquet files
	deepDir := filepath.Join(srcDir, "events", "tenant1", "2026", "07", "24")
	os.MkdirAll(deepDir, 0700)
	os.WriteFile(filepath.Join(deepDir, "file1.parquet"), []byte("data1"), 0644)
	os.WriteFile(filepath.Join(deepDir, "file2.parquet"), []byte("data2"), 0644)

	// Create non-parquet files (should be excluded)
	os.WriteFile(filepath.Join(srcDir, "events", "readme.txt"), []byte("readme"), 0644)

	snapshotPath := filepath.Join(t.TempDir(), "snapshot.tar.gz")
	if err := Create(ctx, snapshotPath, srcDir, nil, nil); err != nil {
		t.Fatal(err)
	}

	dstDir := t.TempDir()
	if err := Restore(ctx, snapshotPath, dstDir); err != nil {
		t.Fatal(err)
	}

	// Parquet files should exist
	if _, err := os.Stat(filepath.Join(dstDir, "events", "tenant1", "2026", "07", "24", "file1.parquet")); os.IsNotExist(err) {
		t.Error("expected file1.parquet to exist after restore")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "events", "tenant1", "2026", "07", "24", "file2.parquet")); os.IsNotExist(err) {
		t.Error("expected file2.parquet to exist after restore")
	}

	// Non-parquet file should NOT be in snapshot
	if _, err := os.Stat(filepath.Join(dstDir, "events", "readme.txt")); err == nil {
		t.Error("expected readme.txt to not be in snapshot")
	}
}
