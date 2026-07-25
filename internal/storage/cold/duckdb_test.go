//go:build cgo

package cold

import (
	"context"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func TestDuckDB_ReadsParquet(t *testing.T) {
	dir := t.TempDir()

	events := []*storage.Event{
		{ID: "ddb-1", TenantID: "t", AgentID: "a", Timestamp: 1000, EventType: "login", Severity: 1},
		{ID: "ddb-2", TenantID: "t", AgentID: "b", Timestamp: 1001, EventType: "alert", Severity: 5},
		{ID: "ddb-3", TenantID: "t", AgentID: "a", Timestamp: 1002, EventType: "logout", Severity: 2},
	}
	path := writeParquetFile(t, dir, "test/2026/07/24", events)

	d := NewDuckDBAnalytics()
	if d.db == nil {
		t.Skip("DuckDB not available")
	}

	result, err := d.QueryFiles(context.Background(), []storage.FileInfo{
		{Path: path},
	}, storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 3 {
		t.Errorf("expected 3 events, got %d", len(result.Events))
	}
}

func TestDuckDB_QueryEquivalence(t *testing.T) {
	dir := t.TempDir()

	events := []*storage.Event{
		{ID: "eq-1", TenantID: "t", AgentID: "agent-a", Timestamp: 100, EventType: "login", Severity: 1, ProcessName: "explorer.exe"},
		{ID: "eq-2", TenantID: "t", AgentID: "agent-b", Timestamp: 200, EventType: "process", Severity: 3},
		{ID: "eq-3", TenantID: "t", AgentID: "agent-a", Timestamp: 300, EventType: "logout", Severity: 2},
		{ID: "eq-4", TenantID: "t", AgentID: "agent-c", Timestamp: 400, EventType: "alert", Severity: 7},
		{ID: "eq-5", TenantID: "t", AgentID: "agent-a", Timestamp: 500, EventType: "login", Severity: 5},
	}
	path := writeParquetFile(t, dir, "test/2026/07/24", events)

	ddb := NewDuckDBAnalytics()
	if ddb.db == nil {
		t.Skip("DuckDB not available")
	}
	pure := NewParquetReader()

	tests := []struct {
		name string
		q    storage.Query
	}{
		{"no filter", storage.Query{Limit: 10}},
		{"agent filter", storage.Query{AgentIDs: []string{"agent-a"}, Limit: 10}},
		{"severity filter", storage.Query{MinSeverity: 4, Limit: 10}},
		{"time range", storage.Query{SinceUs: 200, UntilUs: 500, Limit: 10}},
		{"event type", storage.Query{EventTypes: []string{"alert"}, Limit: 10}},
		{"max id", storage.Query{MaxID: "eq-3", Limit: 10}},
		{"cursor", storage.Query{Cursor: "eq-3", Limit: 10}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			files := []storage.FileInfo{{Path: path}}

			pureResult, pureErr := pure.QueryFiles(ctx, files, tt.q)
			ddbResult, ddbErr := ddb.QueryFiles(ctx, files, tt.q)

			if pureErr != nil {
				t.Fatalf("pure reader error: %v", pureErr)
			}
			if ddbErr != nil {
				t.Fatalf("duckdb error: %v", ddbErr)
			}

			if len(pureResult.Events) != len(ddbResult.Events) {
				t.Errorf("event count mismatch: pure=%d ddb=%d", len(pureResult.Events), len(ddbResult.Events))
				return
			}

			for i := range pureResult.Events {
				if pureResult.Events[i].ID != ddbResult.Events[i].ID {
					t.Errorf("position %d: pure=%s ddb=%s", i, pureResult.Events[i].ID, ddbResult.Events[i].ID)
				}
				if pureResult.Events[i].ProcessName != ddbResult.Events[i].ProcessName {
					t.Errorf("position %d: process_name mismatch", i)
				}
			}
		})
	}
}

func TestDuckDB_ParquetToStorage(t *testing.T) {
	dir := t.TempDir()

	events := []*storage.Event{
		{ID: "conv-1", TenantID: "t1", AgentID: "a", Timestamp: 1000, IngestedAt: 1000, EventType: "login", Severity: 3,
			ProcessName: "svchost.exe", Cmdline: "-k netsvcs", ParentPID: 500, SHA256: "abc123",
			DestIP: "10.0.0.1", SrcIP: "192.168.1.1", UserName: "SYSTEM", Hostname: "WIN-DESKTOP",
			DataRaw: []byte(`{"extra":"data"}`)},
	}
	path := writeParquetFile(t, dir, "test/2026/07/24", events)

	ddb := NewDuckDBAnalytics()
	if ddb.db == nil {
		t.Skip("DuckDB not available")
	}

	result, err := ddb.QueryFiles(context.Background(), []storage.FileInfo{{Path: path}}, storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result.Events))
	}

	e := result.Events[0]
	if e.ID != "conv-1" {
		t.Errorf("ID: %s", e.ID)
	}
	if e.ProcessName != "svchost.exe" {
		t.Errorf("ProcessName: %s", e.ProcessName)
	}
	if e.Cmdline != "-k netsvcs" {
		t.Errorf("Cmdline: %s", e.Cmdline)
	}
	if e.ParentPID != 500 {
		t.Errorf("ParentPID: %d", e.ParentPID)
	}
	if e.SHA256 != "abc123" {
		t.Errorf("SHA256: %s", e.SHA256)
	}
	if e.DestIP != "10.0.0.1" {
		t.Errorf("DestIP: %s", e.DestIP)
	}
	if e.SrcIP != "192.168.1.1" {
		t.Errorf("SrcIP: %s", e.SrcIP)
	}
	if e.UserName != "SYSTEM" {
		t.Errorf("UserName: %s", e.UserName)
	}
	if e.Hostname != "WIN-DESKTOP" {
		t.Errorf("Hostname: %s", e.Hostname)
	}
	if len(e.DataRaw) == 0 {
		t.Error("DataRaw is empty")
	}
}

func TestDuckDB_EmptyFiles(t *testing.T) {
	d := NewDuckDBAnalytics()
	if d.db == nil {
		t.Skip("DuckDB not available")
	}

	result, err := d.QueryFiles(context.Background(), nil, storage.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for nil files, got %d", len(result.Events))
	}

	result, err = d.QueryFiles(context.Background(), []storage.FileInfo{}, storage.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events for empty files, got %d", len(result.Events))
	}
}

func TestDuckDB_FileNotFound(t *testing.T) {
	d := NewDuckDBAnalytics()
	if d.db == nil {
		t.Skip("DuckDB not available")
	}

	_, err := d.QueryFiles(context.Background(), []storage.FileInfo{
		{Path: "/nonexistent/file.parquet"},
	}, storage.Query{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}
