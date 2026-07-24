package cold

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
)

func TestMergeResults_Empty(t *testing.T) {
	r := MergeResults(nil)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if len(r.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(r.Events))
	}
}

func TestMergeResults_Single(t *testing.T) {
	events := []*storage.Event{{ID: "e1"}}
	r := MergeResults([]*storage.Result{{Events: events}})
	if len(r.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(r.Events))
	}
}

func TestMergeResults_Dedup(t *testing.T) {
	r := MergeResults([]*storage.Result{
		{Events: []*storage.Event{{ID: "e1"}, {ID: "e2"}}},
		{Events: []*storage.Event{{ID: "e1"}, {ID: "e3"}}},
	})
	if len(r.Events) != 3 {
		t.Errorf("expected 3 events (deduped), got %d", len(r.Events))
	}
}

func TestMergeResults_SortOrder(t *testing.T) {
	r := MergeResults([]*storage.Result{
		{Events: []*storage.Event{{ID: "z"}, {ID: "a"}}},
		{Events: []*storage.Event{{ID: "m"}}},
	})
	if len(r.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(r.Events))
	}
	expected := []string{"a", "m", "z"}
	for i, e := range r.Events {
		if e.ID != expected[i] {
			t.Errorf("position %d: expected %s, got %s", i, expected[i], e.ID)
		}
	}
}

func TestMergeResults_Warnings(t *testing.T) {
	r := MergeResults([]*storage.Result{
		{Events: []*storage.Event{{ID: "e1"}}, Warnings: []string{"warn1"}},
		{Events: []*storage.Event{{ID: "e2"}}, Warnings: []string{"warn2"}},
	})
	if len(r.Warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d", len(r.Warnings))
	}
}

func TestMergeResults_Cursor(t *testing.T) {
	r := MergeResults([]*storage.Result{
		{Events: []*storage.Event{{ID: "a"}}},
		{Events: []*storage.Event{{ID: "b"}, {ID: "c"}}},
	})
	if r.Cursor != "c" {
		t.Errorf("expected cursor c, got %s", r.Cursor)
	}
}

func TestFilepathList(t *testing.T) {
	files := []storage.FileInfo{
		{Path: "/a/b.parquet"},
		{Path: "/c/d.parquet"},
	}
	paths := filePathList(files)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	if paths[0] != "/a/b.parquet" {
		t.Errorf("expected /a/b.parquet, got %s", paths[0])
	}
}

func TestClampQuery(t *testing.T) {
	tests := []struct {
		name    string
		q       storage.Query
		minID   string
		maxID   string
		wantMin string
		wantMax string
	}{
		{"no clamp", storage.Query{MinID: "b", MaxID: "y"}, "a", "z", "b", "y"},
		{"clamp min", storage.Query{MinID: "0", MaxID: "z"}, "a", "z", "a", "z"},
		{"clamp max", storage.Query{MinID: "a", MaxID: "zz"}, "a", "z", "a", "z"},
		{"both clamped", storage.Query{MinID: "0", MaxID: "zz"}, "a", "z", "a", "z"},
		{"empty min noop", storage.Query{MaxID: "z"}, "a", "z", "", "z"},
		{"empty max noop", storage.Query{MinID: "a"}, "a", "z", "a", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampQuery(tt.q, tt.minID, tt.maxID)
			if got.MinID != tt.wantMin {
				t.Errorf("MinID = %q, want %q", got.MinID, tt.wantMin)
			}
			if got.MaxID != tt.wantMax {
				t.Errorf("MaxID = %q, want %q", got.MaxID, tt.wantMax)
			}
		})
	}
}

func TestParquetReader_Name(t *testing.T) {
	r := NewParquetReader()
	if r.Name() == "" {
		t.Error("expected non-empty name")
	}
}

func writeParquetFile(t *testing.T, dir, partition string, events []*storage.Event) string {
	t.Helper()
	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "out"),
		parquet.DefaultParquetOptions(),
	)
	res, err := pw.WriteBatch(context.Background(), events, partition)
	if err != nil {
		t.Fatal(err)
	}
	pw.Close()
	return res.Path
}

func TestParquetReader_FileNotFound(t *testing.T) {
	r := NewParquetReader()
	result, err := r.QueryFiles(context.Background(), []storage.FileInfo{
		{Path: "/nonexistent/file.parquet"},
	}, storage.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for missing file, got %d", len(result.Events))
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warning for missing file")
	}
}

func TestParquetReader_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "not-parquet.parquet")
	os.WriteFile(badPath, []byte("not a parquet file"), 0644)

	r := NewParquetReader()
	result, err := r.QueryFiles(context.Background(), []storage.FileInfo{
		{Path: badPath},
	}, storage.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events from invalid file, got %d", len(result.Events))
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warning for invalid parquet file")
	}
}

func TestParquetReader_Roundtrip(t *testing.T) {
	dir := t.TempDir()

	events := []*storage.Event{
		{ID: "e1", TenantID: "t1", AgentID: "agent-a", Timestamp: 1000, EventType: "login", Severity: 5, ProcessName: "explorer.exe"},
		{ID: "e2", TenantID: "t1", AgentID: "agent-b", Timestamp: 1001, EventType: "process", Severity: 3},
		{ID: "e3", TenantID: "t1", AgentID: "agent-a", Timestamp: 1002, EventType: "logout", Severity: 1},
		{ID: "e4", TenantID: "t2", AgentID: "agent-c", Timestamp: 1003, EventType: "alert", Severity: 7},
		{ID: "e5", TenantID: "t1", AgentID: "agent-a", Timestamp: 1004, EventType: "login", Severity: 2},
	}
	path := writeParquetFile(t, dir, "test/2026/07/24", events)

	// Single read, verify everything
	r := NewParquetReader()
	result, err := r.QueryFiles(context.Background(), []storage.FileInfo{{Path: path}}, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(result.Events))
	}

	// Verify field preservation
	if result.Events[0].ProcessName != "explorer.exe" {
		t.Errorf("expected process_name preserved, got %q", result.Events[0].ProcessName)
	}
	if result.Events[0].TenantID != "t1" {
		t.Errorf("expected tenant t1, got %s", result.Events[0].TenantID)
	}

	// Verify cursor
	if result.Cursor == "" {
		t.Error("expected non-empty cursor")
	}
}

func TestParquetReader_MultipleFiles(t *testing.T) {
	dir := t.TempDir()

	p1 := writeParquetFile(t, dir, "test/2026/07/24/10", []*storage.Event{
		{ID: "a1", TenantID: "t", AgentID: "a", Timestamp: 100, EventType: "test", Severity: 1},
		{ID: "a2", TenantID: "t", AgentID: "a", Timestamp: 200, EventType: "test", Severity: 1},
	})
	p2 := writeParquetFile(t, dir, "test/2026/07/24/11", []*storage.Event{
		{ID: "b1", TenantID: "t", AgentID: "b", Timestamp: 300, EventType: "test", Severity: 2},
		{ID: "b2", TenantID: "t", AgentID: "b", Timestamp: 400, EventType: "test", Severity: 2},
	})

	r := NewParquetReader()
	result, err := r.QueryFiles(context.Background(), []storage.FileInfo{
		{Path: p1},
		{Path: p2},
	}, storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 4 {
		t.Errorf("expected 4 events from 2 files, got %d", len(result.Events))
	}
}
