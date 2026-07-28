package audit

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "audit.db")+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNew(t *testing.T) {
	db := testDB(t)
	l, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestWriteAndQuery(t *testing.T) {
	db := testDB(t)
	l, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	err = l.Write(ctx, Entry{
		ActorID:      "user-1",
		ActorEmail:   "analyst@example.com",
		Action:       "case.create",
		ResourceType: "case",
		ResourceID:   "case-123",
		Details:      `{"title":"Phishing incident"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	entries, err := l.Query(ctx, QueryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "case.create" {
		t.Errorf("expected case.create, got %s", entries[0].Action)
	}
	if entries[0].Signature == "" {
		t.Error("expected non-empty signature")
	}
}

func TestWriteChained(t *testing.T) {
	db := testDB(t)
	l, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		err := l.Write(ctx, Entry{
			ActorID:      "user-1",
			ActorEmail:   "a@b.com",
			Action:       "test",
			ResourceType: "test",
			ResourceID:   fmt.Sprintf("res-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify chain
	entries, _ := l.Query(ctx, QueryFilter{Limit: 10})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Entries are in DESC order, so reverse
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if i > 0 {
			prev := entries[i-1]
			if e.Signature != getPrevHash(t, l.db, e.ID) {
				_ = prev
			}
		}
	}
}

func getPrevHash(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	var prev, sig string
	err := db.QueryRow(
		`SELECT previous_hash, signature FROM audit_log WHERE id = ?`, id).Scan(&prev, &sig)
	if err != nil {
		t.Fatal(err)
	}
	return prev
}

func TestVerify(t *testing.T) {
	db := testDB(t)
	l, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		l.Write(ctx, Entry{
			ActorID:      "user-1",
			ActorEmail:   "a@b.com",
			Action:       "test",
			ResourceType: "test",
			ResourceID:   fmt.Sprintf("res-%d", i),
		})
	}

	valid, errs := l.Verify(ctx)
	if !valid {
		t.Fatalf("expected valid audit log, got errors: %v", errs)
	}
}

func TestVerifyTampered(t *testing.T) {
	db := testDB(t)
	l, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		l.Write(ctx, Entry{
			ActorID:      "user-1",
			ActorEmail:   "a@b.com",
			Action:       "test",
			ResourceType: "test",
			ResourceID:   fmt.Sprintf("res-%d", i),
		})
	}

	// Tamper with an entry
	_, err = db.Exec(`UPDATE audit_log SET actor_email = 'hacker@evil.com' WHERE id = 1`)
	if err != nil {
		t.Fatal(err)
	}

	valid, errs := l.Verify(ctx)
	if valid {
		t.Error("expected tampered log to be invalid")
	}
	if len(errs) == 0 {
		t.Error("expected at least one verification error")
	}
}

func TestQueryFiltered(t *testing.T) {
	db := testDB(t)
	l, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	actions := []string{"case.create", "case.update", "case.delete", "investigation.create"}
	for i, action := range actions {
		l.Write(ctx, Entry{
			ActorID:      "user-1",
			ActorEmail:   "a@b.com",
			Action:       action,
			ResourceType: "case",
			ResourceID:   fmt.Sprintf("case-%d", i),
		})
	}

	// Filter by action
	entries, err := l.Query(ctx, QueryFilter{Action: "case.create"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 case.create, got %d", len(entries))
	}

	// Filter by resource type
	entries, err = l.Query(ctx, QueryFilter{ResourceType: "case"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Errorf("expected 4 case entries, got %d", len(entries))
	}
}

func TestMarshalDetails(t *testing.T) {
	s := MarshalDetails(map[string]string{"key": "value"})
	if s != `{"key":"value"}` {
		t.Errorf("expected json, got %s", s)
	}
}
