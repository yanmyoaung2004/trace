package db

import (
	"testing"
)

func TestDetectDriver(t *testing.T) {
	tests := []struct {
		dsn  string
		want string
	}{
		{"/tmp/test.db", "sqlite"},
		{"./data/trace.db", "sqlite"},
		{"postgres://user:pass@localhost/trace", "postgres"},
		{"postgresql://user:pass@localhost/trace", "postgres"},
		{"pgx://user:pass@localhost/trace", "postgres"},
	}
	for _, tt := range tests {
		got := detectDriver(tt.dsn)
		if got != tt.want {
			t.Errorf("detectDriver(%q) = %q, want %q", tt.dsn, got, tt.want)
		}
	}
}

func TestTranslate_NoopForSQLite(t *testing.T) {
	d := &DB{driver: "sqlite"}
	q := "SELECT * FROM test WHERE id = ?"
	got := d.translate(q)
	if got != q {
		t.Errorf("sqlite translate changed query: %s -> %s", q, got)
	}
}

func TestTranslate_PositionalPlaceholders(t *testing.T) {
	d := &DB{driver: "postgres"}
	q := d.translate("SELECT * FROM test WHERE id = ? AND name = ?")
	want := "SELECT * FROM test WHERE id = $1 AND name = $2"
	if q != want {
		t.Errorf("got %q, want %q", q, want)
	}
}

func TestTranslate_DateTime(t *testing.T) {
	d := &DB{driver: "postgres"}
	q := d.translate("SELECT * FROM t WHERE created_at = datetime('now')")
	want := "SELECT * FROM t WHERE created_at = NOW()"
	if q != want {
		t.Errorf("got %q, want %q", q, want)
	}
}

func TestTranslate_Strftime(t *testing.T) {
	d := &DB{driver: "postgres"}
	q := d.translate("CAST(strftime('%s','now') AS INTEGER)")
	want := "EXTRACT(EPOCH FROM NOW())::INTEGER"
	if q != want {
		t.Errorf("got %q, want %q", q, want)
	}
}

func TestTranslate_InsertOrIgnore(t *testing.T) {
	d := &DB{driver: "postgres"}
	q := d.translate("INSERT OR IGNORE INTO test VALUES (?)")
	if !contains(q, "ON CONFLICT DO NOTHING") {
		t.Errorf("expected ON CONFLICT DO NOTHING, got %q", q)
	}
}

func TestTranslate_MultiplePlaceholders(t *testing.T) {
	d := &DB{driver: "postgres"}
	q := d.translate("INSERT INTO t VALUES (?, ?, ?, ?)")
	want := "INSERT INTO t VALUES ($1, $2, $3, $4)"
	if q != want {
		t.Errorf("got %q, want %q", q, want)
	}
}

func TestTranslate_ComplexQuery(t *testing.T) {
	d := &DB{driver: "postgres"}
	q := d.translate(`
		INSERT INTO edr_agents (id, hostname, status, last_heartbeat, created_at)
		VALUES (?, ?, 'active', datetime('now'), datetime('now'))
		ON CONFLICT(id) DO UPDATE SET last_heartbeat = datetime('now')
	`)
	if !contains(q, "$1") || !contains(q, "$2") {
		t.Errorf("expected $1 and $2 placeholders, got %q", q)
	}
	if contains(q, "datetime('now')") {
		t.Errorf("expected NOW(), got datetime('now'): %q", q)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
