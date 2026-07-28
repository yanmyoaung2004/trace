package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

func TestNewScheduler(t *testing.T) {
	s := NewScheduler(Config{
		Interval:   10 * time.Minute,
		BackupDir:  t.TempDir(),
		MaxBackups: 3,
	})
	if s == nil {
		t.Fatal("expected non-nil scheduler")
	}
}

func TestSchedulerRunBackup(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backups")
	os.MkdirAll(backupDir, 0700)

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

	f := flusher.NewFlusher(hot, m, pw, 0, 100, 1000, filepath.Join(dir, "events"))

	s := NewScheduler(Config{
		Interval:   1 * time.Hour,
		BackupDir:  backupDir,
		MaxBackups: 3,
		DataDir:    dir,
	})

	ctx := context.Background()
	s.runBackup(ctx, f, m)

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least 1 backup file")
	}
	t.Logf("backup file: %s", entries[0].Name())
}

func TestSchedulerRotation(t *testing.T) {
	dir := t.TempDir()
	backupDir := filepath.Join(dir, "backups")
	os.MkdirAll(backupDir, 0700)

	for i := 0; i < 5; i++ {
		f, _ := os.Create(filepath.Join(backupDir, fmt.Sprintf("tse-snapshot-%d.tar.gz", i)))
		f.Write([]byte("data"))
		f.Close()
	}

	s := NewScheduler(Config{
		BackupDir:  backupDir,
		MaxBackups: 2,
	})
	s.rotateLocal()

	entries, _ := os.ReadDir(backupDir)
	if len(entries) > 2 {
		t.Errorf("expected max 2 backups, got %d", len(entries))
	}
}

func TestFileSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello"), 0644)

	sz := fileSize(path)
	if sz != 5 {
		t.Errorf("expected 5, got %d", sz)
	}

	sz2 := fileSize("/nonexistent")
	if sz2 != 0 {
		t.Errorf("expected 0 for missing file, got %d", sz2)
	}
}
