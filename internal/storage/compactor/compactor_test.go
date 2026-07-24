package compactor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
)

type mockColdReader struct {
	events map[string][]*storage.Event
}

func (m *mockColdReader) QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error) {
	events := make([]*storage.Event, 0)
	for _, f := range files {
		if evts, ok := m.events[f.Path]; ok {
			events = append(events, evts...)
		}
	}
	return &storage.Result{Events: events}, nil
}

func (m *mockColdReader) Name() string { return "mock" }

func TestNewCompactor(t *testing.T) {
	m, _ := manifest.NewManifest(filepath.Join(t.TempDir(), "manifest.db"))
	defer m.Close()
	cr := &mockColdReader{}
	pw := parquet.NewParquetWriter(t.TempDir(), t.TempDir(), parquet.DefaultParquetOptions())
	defer pw.Close()

	c := NewCompactor(m, cr, pw, 0)
	if c == nil {
		t.Fatal("expected non-nil compactor")
	}
}

func TestCompactor_RunCancel(t *testing.T) {
	m, _ := manifest.NewManifest(filepath.Join(t.TempDir(), "manifest.db"))
	defer m.Close()
	cr := &mockColdReader{}
	pw := parquet.NewParquetWriter(t.TempDir(), t.TempDir(), parquet.DefaultParquetOptions())
	defer pw.Close()

	c := NewCompactor(m, cr, pw, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := c.Run(ctx)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestCompactor_CleanupSuperseded(t *testing.T) {
	dir := t.TempDir()
	m, _ := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()

	cr := &mockColdReader{}
	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "events"),
		parquet.DefaultParquetOptions(),
	)
	defer pw.Close()

	c := NewCompactor(m, cr, pw, 0)
	c.grace = 10 * time.Millisecond

	// Create a superseded file
	fakePath := filepath.Join(dir, "events", "superseded.parquet")
	os.MkdirAll(filepath.Dir(fakePath), 0700)
	os.WriteFile(fakePath, []byte("data"), 0644)

	ctx := context.Background()
	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "f1",
		Path:           fakePath,
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: 1,
		MaxTimestampUs: 1,
		MinEventID:     "a",
		MaxEventID:     "b",
		SHA256:         "sha",
	})
	// AddFile always sets status=committed, update to superseded
	m.UpdateFileStatus(ctx, "f1", "superseded")

	// Wait for grace period
	time.Sleep(50 * time.Millisecond)

	if err := c.CleanupSuperseded(ctx); err != nil {
		t.Fatal(err)
	}

	// File should be deleted
	if _, err := os.Stat(fakePath); !os.IsNotExist(err) {
		t.Error("expected superseded file to be deleted after grace period")
	}
}

func TestCompactor_CleanupSuperseded_GraceNotElapsed(t *testing.T) {
	dir := t.TempDir()
	m, _ := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()

	cr := &mockColdReader{}
	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "events"),
		parquet.DefaultParquetOptions(),
	)
	defer pw.Close()

	c := NewCompactor(m, cr, pw, 0)
	c.grace = 1 * time.Hour // long grace

	fakePath := filepath.Join(dir, "events", "recent.parquet")
	os.MkdirAll(filepath.Dir(fakePath), 0700)
	os.WriteFile(fakePath, []byte("data"), 0644)

	ctx := context.Background()
	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "f2",
		Path:           fakePath,
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: time.Now().UnixMicro(),
		MaxTimestampUs: time.Now().UnixMicro(),
		MinEventID:     "a",
		MaxEventID:     "b",
		SHA256:         "sha",
	})
	m.UpdateFileStatus(ctx, "f2", "superseded")

	if err := c.CleanupSuperseded(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(fakePath); os.IsNotExist(err) {
		t.Error("expected file to remain within grace period")
	}
}

func TestCompactor_FormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{500, "500B"},
		{1024, "1KB"},
		{2048, "2KB"},
		{1048576, "1MB"},
		{2097152, "2MB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatBytes(tt.input)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestCompactor_CompactionCreatesDaily(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	outputDir := filepath.Join(dir, "events")

	m, _ := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	defer m.Close()

	// Write two hourly files with old timestamps ( > 48h ago )
	oldTime := time.Now().Add(-72 * time.Hour)
	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		outputDir,
		parquet.DefaultParquetOptions(),
	)

	r1, err := pw.WriteBatch(ctx, []*storage.Event{
		{ID: "h1-a", TenantID: "t", AgentID: "a", Timestamp: oldTime.UnixMicro(), EventType: "login", Severity: 1},
		{ID: "h1-b", TenantID: "t", AgentID: "b", Timestamp: oldTime.UnixMicro() + 1, EventType: "process", Severity: 2},
		{ID: "h1-c", TenantID: "t", AgentID: "a", Timestamp: oldTime.UnixMicro() + 2, EventType: "login", Severity: 1},
	}, fmt.Sprintf("t/%s/10", oldTime.Format("2006-01-02")))
	if err != nil {
		t.Fatal(err)
	}

	r2, err := pw.WriteBatch(ctx, []*storage.Event{
		{ID: "h2-a", TenantID: "t", AgentID: "a", Timestamp: oldTime.UnixMicro() + 1000, EventType: "logout", Severity: 1},
		{ID: "h2-b", TenantID: "t", AgentID: "b", Timestamp: oldTime.UnixMicro() + 1001, EventType: "alert", Severity: 5},
	}, fmt.Sprintf("t/%s/11", oldTime.Format("2006-01-02")))
	if err != nil {
		t.Fatal(err)
	}
	pw.Close()

	// Register both files in manifest as committed
	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "f1",
		Path:           r1.Path,
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: r1.MinTimestampUs,
		MaxTimestampUs: r1.MaxTimestampUs,
		MinEventID:     r1.MinEventID,
		MaxEventID:     r1.MaxEventID,
		RowCount:       r1.RowCount,
		CompressedSize: r1.CompressedSize,
		SHA256:         r1.SHA256,
	})
	m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "f2",
		Path:           r2.Path,
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: r2.MinTimestampUs,
		MaxTimestampUs: r2.MaxTimestampUs,
		MinEventID:     r2.MinEventID,
		MaxEventID:     r2.MaxEventID,
		RowCount:       r2.RowCount,
		CompressedSize: r2.CompressedSize,
		SHA256:         r2.SHA256,
	})

	// Create compactor with real cold reader
	pw2 := parquet.NewParquetWriter(
		filepath.Join(dir, "temp-compact"),
		outputDir,
		parquet.DefaultParquetOptions(),
	)
	defer pw2.Close()

	cr := cold.NewParquetReader()
	c := NewCompactor(m, cr, pw2, 0)

	// Call compactOnce directly (same package, unexported is accessible)
	c.compactOnce(ctx)

	// Verify: one daily file should be committed
	files, err := m.FilesFor(ctx, "t", 0, 0, "committed")
	if err != nil {
		t.Fatal(err)
	}

	dailyFiles := 0
	for _, f := range files {
		if f.Level == 1 {
			dailyFiles++
		}
	}
	if dailyFiles == 0 {
		t.Error("expected at least 1 daily file after compaction")
	}

	// Original hourly files should now be superseded
	hourlySuperseded, _ := m.FilesFor(ctx, "t", 0, 0, "superseded")
	if len(hourlySuperseded) == 0 {
		t.Error("expected hourly files to be marked as superseded")
	}
}
