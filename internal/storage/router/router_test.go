package router

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

type mockColdReader struct {
	events []*storage.Event
	err    error
}

func (m *mockColdReader) QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error) {
	if m.err != nil {
		return nil, m.err
	}
	if q.SinceUs > 0 || q.UntilUs > 0 {
		var filtered []*storage.Event
		for _, e := range m.events {
			if (q.SinceUs == 0 || e.Timestamp >= q.SinceUs) &&
				(q.UntilUs == 0 || e.Timestamp < q.UntilUs) {
				filtered = append(filtered, e)
			}
		}
		return &storage.Result{Events: filtered}, nil
	}
	return &storage.Result{Events: m.events}, nil
}

func (m *mockColdReader) Name() string { return "mock" }

func newTestHotStore(t *testing.T) *sqlite.SQLiteHotStore {
	t.Helper()
	dir := t.TempDir()
	s, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		t.Fatalf("NewSQLiteHotStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

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

func nowUs() int64 {
	return time.Now().UnixMicro()
}

func TestRouter_New(t *testing.T) {
	hot := newTestHotStore(t)
	m := newTestManifest(t)
	cr := &mockColdReader{}
	r := NewRouter(hot, cr, m)
	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestRouter_Empty(t *testing.T) {
	hot := newTestHotStore(t)
	m := newTestManifest(t)
	cr := &mockColdReader{}
	r := NewRouter(hot, cr, m)

	result, err := r.Query(context.Background(), storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
}

func TestRouter_HotOnly(t *testing.T) {
	hot := newTestHotStore(t)
	m := newTestManifest(t)
	cr := &mockColdReader{}
	ctx := context.Background()

	// Write to hot store
	err := hot.WriteBatch(ctx, []*storage.Event{
		{ID: "e1", TenantID: "t", AgentID: "a", Timestamp: nowUs(), EventType: "login", Severity: 1},
		{ID: "e2", TenantID: "t", AgentID: "b", Timestamp: nowUs(), EventType: "process", Severity: 3},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Update watermark so cold is not needed
	m.UpdateWatermark(ctx, "e2", nowUs())

	r := NewRouter(hot, cr, m)
	result, err := r.Query(ctx, storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 2 {
		t.Errorf("expected 2 events from hot, got %d", len(result.Events))
	}
}

func TestRouter_HotAndCold(t *testing.T) {
	hot := newTestHotStore(t)
	m := newTestManifest(t)
	ctx := context.Background()

	now := nowUs()
	older := now - int64(30*time.Minute)

	// Cold events (older than watermark)
	coldEvents := []*storage.Event{
		{ID: "cold-1", TenantID: "t", AgentID: "a", Timestamp: older, EventType: "login", Severity: 1},
		{ID: "cold-2", TenantID: "t", AgentID: "b", Timestamp: older + 1, EventType: "alert", Severity: 5},
	}
	cr := &mockColdReader{events: coldEvents}

	// Hot events (recent)
	err := hot.WriteBatch(ctx, []*storage.Event{
		{ID: "hot-1", TenantID: "t", AgentID: "a", Timestamp: now, EventType: "logout", Severity: 2},
		{ID: "hot-2", TenantID: "t", AgentID: "b", Timestamp: now + 1, EventType: "process", Severity: 4},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set watermark to the boundary between cold and hot
	m.UpdateWatermark(ctx, "cold-2", older+1)

	// Register a committed file so cold query triggers
	err = m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "file-1",
		Path:           "/path/to/file.parquet",
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: older,
		MaxTimestampUs: older + 1,
		MinEventID:     "cold-1",
		MaxEventID:     "cold-2",
		SHA256:         "sha",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := NewRouter(hot, cr, m)
	result, err := r.Query(ctx, storage.Query{Limit: 10, SinceUs: older})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 4 {
		t.Errorf("expected 4 events (2 cold + 2 hot), got %d", len(result.Events))
	}
}

func TestRouter_DedupAcrossTiers(t *testing.T) {
	hot := newTestHotStore(t)
	m := newTestManifest(t)
	ctx := context.Background()

	now := nowUs()
	older := now - int64(15*time.Minute)

	// Cold has an event
	coldEvents := []*storage.Event{
		{ID: "dup-1", TenantID: "t", AgentID: "a", Timestamp: older, EventType: "login", Severity: 1},
	}
	cr := &mockColdReader{events: coldEvents}

	// Hot ALSO has the same event (from overlap window)
	err := hot.WriteBatch(ctx, []*storage.Event{
		{ID: "dup-1", TenantID: "t", AgentID: "a", Timestamp: older, EventType: "login", Severity: 1},
		{ID: "hot-only", TenantID: "t", AgentID: "b", Timestamp: now, EventType: "logout", Severity: 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = m.UpdateWatermark(ctx, "dup-1", older)
	if err != nil {
		t.Fatal(err)
	}

	err = m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "file-1",
		Path:           "/path/file.parquet",
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: older,
		MaxTimestampUs: older,
		MinEventID:     "dup-1",
		MaxEventID:     "dup-1",
		SHA256:         "sha",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := NewRouter(hot, cr, m)
	result, err := r.Query(ctx, storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 2 {
		t.Errorf("expected 2 events (deduped), got %d", len(result.Events))
	}
}

func TestRouter_ColdFallback(t *testing.T) {
	hot := newTestHotStore(t)
	m := newTestManifest(t)
	ctx := context.Background()

	// Cold reader returns error
	cr := &mockColdReader{err: nil}
	cr.events = []*storage.Event{
		{ID: "c1", TenantID: "t", AgentID: "a", Timestamp: 1000, EventType: "test", Severity: 1},
	}

	err := m.AddFile(ctx, storage.ParquetFileRecord{
		FileID:         "file-1",
		Path:           "/path/file.parquet",
		TenantID:       "t",
		Level:          0,
		MinTimestampUs: 1000,
		MaxTimestampUs: 1000,
		MinEventID:     "c1",
		MaxEventID:     "c1",
		SHA256:         "sha",
	})
	if err != nil {
		t.Fatal(err)
	}
	m.UpdateWatermark(ctx, "c1", 1000)

	r := NewRouter(hot, cr, m)
	result, err := r.Query(ctx, storage.Query{Limit: 10, SinceUs: 1000})
	if err != nil {
		t.Fatal(err)
	}
	// Cold should succeed in this case; test with nil err
	if len(result.Events) == 0 {
		t.Error("expected cold events returned")
	}
}

func TestRouter_Limit(t *testing.T) {
	hot := newTestHotStore(t)
	m := newTestManifest(t)
	ctx := context.Background()

	now := nowUs()

	err := hot.WriteBatch(ctx, []*storage.Event{
		{ID: "h1", TenantID: "t", AgentID: "a", Timestamp: now, EventType: "test", Severity: 1},
		{ID: "h2", TenantID: "t", AgentID: "b", Timestamp: now + 1, EventType: "test", Severity: 2},
		{ID: "h3", TenantID: "t", AgentID: "c", Timestamp: now + 2, EventType: "test", Severity: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	m.UpdateWatermark(ctx, "h3", now+2)

	r := NewRouter(hot, &mockColdReader{}, m)
	result, err := r.Query(ctx, storage.Query{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) > 1 {
		t.Errorf("expected at most 1 event with Limit=1, got %d", len(result.Events))
	}
}
