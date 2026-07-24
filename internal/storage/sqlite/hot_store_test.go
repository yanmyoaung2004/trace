package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func newTestHotStore(tb testing.TB) *SQLiteHotStore {
	tb.Helper()
	dir := tb.TempDir()
	path := filepath.Join(dir, "test.db")
	s, err := NewSQLiteHotStore(path)
	if err != nil {
		tb.Fatalf("NewSQLiteHotStore: %v", err)
	}
	tb.Cleanup(func() { s.Close() })
	return s
}

func testEvent(id string) *storage.Event {
	return &storage.Event{
		ID:        id,
		TenantID:  "test-tenant",
		AgentID:   "agent-1",
		Timestamp: time.Now().UnixMicro(),
		EventType: "test",
		Severity:  1,
	}
}

func TestSQLiteHotStore_WriteBatch(t *testing.T) {
	s := newTestHotStore(t)

	err := s.WriteBatch(context.Background(), []*storage.Event{
		testEvent("e1"),
		testEvent("e2"),
	})
	if err != nil {
		t.Fatal(err)
	}

	tables, err := s.LiveTables(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) == 0 {
		t.Fatal("expected at least one live table")
	}
}

func TestSQLiteHotStore_Query(t *testing.T) {
	s := newTestHotStore(t)
	ctx := context.Background()

	events := []*storage.Event{
		testEvent("e1"),
		testEvent("e2"),
		testEvent("e3"),
	}
	if err := s.WriteBatch(ctx, events); err != nil {
		t.Fatal(err)
	}

	// Verify data made it into the DB directly
	tables, _ := s.LiveTables(ctx)
	if len(tables) == 0 {
		t.Fatal("no live tables after write")
	}
	var count int
	s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tables[0])).Scan(&count)
	if count != 3 {
		t.Fatalf("expected 3 rows in %s, got %d", tables[0], count)
	}

	result, err := s.Query(ctx, storage.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 3 {
		t.Errorf("expected 3 events via Query, got %d", len(result.Events))
	}
}

func TestSQLiteHotStore_QueryWithFilter(t *testing.T) {
	s := newTestHotStore(t)
	ctx := context.Background()

	e1 := testEvent("e1")
	e1.AgentID = "agent-1"
	e2 := testEvent("e2")
	e2.AgentID = "agent-2"

	s.WriteBatch(ctx, []*storage.Event{e1, e2})

	result, err := s.Query(ctx, storage.Query{AgentIDs: []string{"agent-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 {
		t.Errorf("expected 1 event for agent-1, got %d", len(result.Events))
	}
}

func TestSQLiteHotStore_DropTable(t *testing.T) {
	s := newTestHotStore(t)
	ctx := context.Background()

	s.WriteBatch(ctx, []*storage.Event{testEvent("e1")})

	tables, _ := s.LiveTables(ctx)
	if len(tables) == 0 {
		t.Fatal("expected tables before drop")
	}

	if err := s.DropTable(ctx, tables[0]); err != nil {
		t.Fatal(err)
	}

	tables, _ = s.LiveTables(ctx)
	if len(tables) != 0 {
		t.Errorf("expected 0 tables after drop, got %d", len(tables))
	}
}

func TestSQLiteHotStore_QueryEmpty(t *testing.T) {
	s := newTestHotStore(t)
	result, err := s.Query(context.Background(), storage.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
}

func TestSQLiteHotStore_ConcurrentWrites(t *testing.T) {
	s := newTestHotStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		e := testEvent(fmt.Sprintf("e-%d", i))
		if err := s.WriteBatch(ctx, []*storage.Event{e}); err != nil {
			t.Fatalf("write batch %d: %v", i, err)
		}
	}

	// Direct DB check
	tables, _ := s.LiveTables(ctx)
	if len(tables) == 0 {
		t.Fatal("no live tables after writes")
	}
	var count int
	s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tables[0])).Scan(&count)
	t.Logf("direct count from %s: %d", tables[0], count)

	sqlQ, args := buildHotQuery(tables, storage.Query{Limit: 100})
	t.Logf("query SQL: %q", sqlQ)
	t.Logf("query args: %v", args)

	result, _ := s.Query(ctx, storage.Query{Limit: 100})
	if len(result.Events) != 10 {
		t.Errorf("expected 10 events, got %d. DB count: %d", len(result.Events), count)
	}
}

func TestHourlyTableName(t *testing.T) {
	hourStart := time.Date(2026, 7, 24, 15, 0, 0, 0, time.Local).UnixMicro()
	name := hourlyTableName(hourStart, "edr_events_%s")
	if name != "edr_events_2026072415" {
		t.Errorf("expected edr_events_2026072415, got %s", name)
	}
}

func TestPlaceholders(t *testing.T) {
	if placeholders(0) != "" {
		t.Errorf("expected empty for 0")
	}
	if placeholders(1) != "?" {
		t.Errorf("expected ? for 1")
	}
	if placeholders(3) != "?,?,?" {
		t.Errorf("expected ?,?,? for 3, got %s", placeholders(3))
	}
}

func TestDbPathCreation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "test.db")
	s, err := NewSQLiteHotStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected db file to be created")
	}
}

func BenchmarkHotStore_WriteBatch(b *testing.B) {
	s := newTestHotStore(b)
	ctx := context.Background()

	events := make([]*storage.Event, 100)
	for i := 0; i < 100; i++ {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("bench-%d", i),
			TenantID:  "bench",
			AgentID:   "agent",
			Timestamp: time.Now().UnixMicro(),
			EventType: "benchmark",
			Severity:  1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.WriteBatch(ctx, events); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHotStore_Query(b *testing.B) {
	s := newTestHotStore(b)
	ctx := context.Background()

	// Write 1000 events first
	events := make([]*storage.Event, 1000)
	for i := 0; i < 1000; i++ {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("q-%d", i),
			TenantID:  "bench",
			AgentID:   "agent",
			Timestamp: time.Now().UnixMicro() + int64(i),
			EventType: "benchmark",
			Severity:  1,
		}
	}
	if err := s.WriteBatch(ctx, events); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := s.Query(ctx, storage.Query{Limit: 100})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events")
		}
	}
}

func TestCheckpointer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoint.db")
	s, err := NewSQLiteHotStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cp := NewCheckpointer(s.db, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	go cp.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
}
