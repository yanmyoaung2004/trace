package parquet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func TestParquetWriter_WriteBatch(t *testing.T) {
	dir := t.TempDir()
	tempDir := filepath.Join(dir, "temp")
	outputDir := filepath.Join(dir, "output")

	w := NewParquetWriter(tempDir, outputDir, DefaultParquetOptions())

	events := []*storage.Event{
		{
			ID:        "e1",
			TenantID:  "test",
			AgentID:   "agent-1",
			Timestamp: time.Now().UnixMicro(),
			EventType: "test",
			Severity:  1,
		},
		{
			ID:        "e2",
			TenantID:  "test",
			AgentID:   "agent-2",
			Timestamp: time.Now().UnixMicro(),
			EventType: "test",
			Severity:  5,
		},
	}

	result, err := w.WriteBatch(context.Background(), events, "test-tenant/2026/07/24/15")
	if err != nil {
		t.Fatal(err)
	}

	if result.RowCount != 2 {
		t.Errorf("expected 2 rows, got %d", result.RowCount)
	}
	if result.SHA256 == "" {
		t.Error("expected non-empty SHA256")
	}
	if result.Path == "" {
		t.Error("expected non-empty path")
	}

	// Verify file exists
	if _, err := os.Stat(result.Path); os.IsNotExist(err) {
		t.Errorf("expected file to exist: %s", result.Path)
	}

	// Verify temp files are cleaned up (temp should be empty after successful write)
	tempEntries, _ := os.ReadDir(tempDir)
	if len(tempEntries) != 0 {
		t.Errorf("expected temp dir empty, got %d entries", len(tempEntries))
	}
}

func TestParquetWriter_SortOrder(t *testing.T) {
	dir := t.TempDir()
	w := NewParquetWriter(filepath.Join(dir, "temp"), filepath.Join(dir, "output"), DefaultParquetOptions())

	// Events in reverse agent order
	events := []*storage.Event{
		{ID: "e2", TenantID: "test", AgentID: "z-agent", Timestamp: 200},
		{ID: "e1", TenantID: "test", AgentID: "a-agent", Timestamp: 100},
	}

	result, err := w.WriteBatch(context.Background(), events, "test/2026/07/24/15")
	if err != nil {
		t.Fatal(err)
	}

	if result.MinEventID != "e1" {
		t.Errorf("expected min id e1 (first sorted), got %s", result.MinEventID)
	}
}

func TestParquetWriter_LargeBatch(t *testing.T) {
	dir := t.TempDir()
	w := NewParquetWriter(filepath.Join(dir, "temp"), filepath.Join(dir, "output"), DefaultParquetOptions())

	n := 1000
	events := make([]*storage.Event, n)
	for i := 0; i < n; i++ {
		events[i] = &storage.Event{
			ID:        "e",
			TenantID:  "test",
			AgentID:   "agent",
			Timestamp: int64(i),
			EventType: "test",
			Severity:  1,
		}
	}

	result, err := w.WriteBatch(context.Background(), events, "test/2026/07/24/15")
	if err != nil {
		t.Fatal(err)
	}

	if result.RowCount != n {
		t.Errorf("expected %d rows, got %d", n, result.RowCount)
	}
}

func BenchmarkParquetWriter_WriteBatch(b *testing.B) {
	dir := b.TempDir()
	w := NewParquetWriter(filepath.Join(dir, "temp"), filepath.Join(dir, "output"), DefaultParquetOptions())

	events := make([]*storage.Event, 100)
	for i := 0; i < 100; i++ {
		events[i] = &storage.Event{
			ID:        "e",
			TenantID:  "bench",
			AgentID:   "agent",
			Timestamp: int64(i),
			EventType: "benchmark",
			Severity:  1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := w.WriteBatch(context.Background(), events, "bench/2026/07/24/15")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestParquetWriter_EmptyBatchError(t *testing.T) {
	dir := t.TempDir()
	w := NewParquetWriter(filepath.Join(dir, "temp"), filepath.Join(dir, "output"), DefaultParquetOptions())

	_, err := w.WriteBatch(context.Background(), nil, "test")
	if err == nil {
		t.Fatal("expected error for empty batch")
	}
}
