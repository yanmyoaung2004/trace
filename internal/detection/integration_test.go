package detection

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "cache.db")+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cache (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		ttl INTEGER NOT NULL DEFAULT 3600,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAgentCapabilities(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	caps := a.Capabilities()
	if len(caps) == 0 {
		t.Fatal("expected capabilities")
	}
	expected := map[string]bool{"yara_scan": false, "pe_analyze": false, "hash_lookup": false, "vt_lookup": false}
	for _, c := range caps {
		if _, ok := expected[c.Action]; !ok {
			t.Errorf("unexpected action: %s", c.Action)
		}
		expected[c.Action] = true
	}
	for action, found := range expected {
		if !found {
			t.Errorf("missing action: %s", action)
		}
	}
}

func TestAgentName(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	if a.Name() != "detection" {
		t.Errorf("Name() = %q, want %q", a.Name(), "detection")
	}
}

func TestHashLookup_Unknown(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	out, err := a.Execute(ctx, map[string]any{
		"action": "hash_lookup",
		"hash":   "00000000000000000000000000000000",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rep, _ := out["reputation"].(string)
	if rep != "unknown" {
		t.Errorf("expected unknown reputation, got %q", rep)
	}
}

func TestHashLookup_Mimikatz(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	out, err := a.Execute(ctx, map[string]any{
		"action": "hash_lookup",
		"hash":   "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rep, _ := out["reputation"].(string)
	if rep != "malicious" {
		t.Errorf("expected malicious reputation, got %q", rep)
	}
}

func TestHashLookup_EICAR(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	out, err := a.Execute(ctx, map[string]any{
		"action": "hash_lookup",
		"hash":   "e99a18c428cb38d5f260853678922e03",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rep, _ := out["reputation"].(string)
	if rep != "malicious" {
		t.Errorf("expected malicious reputation, got %q", rep)
	}
}

func TestHashLookup_MissingHash(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	out, err := a.Execute(ctx, map[string]any{
		"action": "hash_lookup",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	errStr, _ := out["error"].(string)
	if errStr == "" {
		t.Error("expected error for missing hash")
	}
}

func TestYaraScan_EICAR(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	tmpDir := t.TempDir()
	eicarPath := filepath.Join(tmpDir, "eicar.txt")
	os.WriteFile(eicarPath, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), 0644)

	out, err := a.Execute(ctx, map[string]any{
		"action": "yara_scan",
		"path":   eicarPath,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	count, _ := out["count"].(int)
	if count == 0 {
		t.Error("expected YARA match for EICAR file")
	}
}

func TestYaraScan_NoFile(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	out, err := a.Execute(ctx, map[string]any{
		"action": "yara_scan",
		"path":   "/nonexistent/file.exe",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	errStr, _ := out["error"].(string)
	if errStr == "" {
		t.Error("expected error for nonexistent file")
	}
}

func TestPEAnalyze_NotPE(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	tmpDir := t.TempDir()
	txtPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(txtPath, []byte("not a PE file"), 0644)

	out, err := a.Execute(ctx, map[string]any{
		"action": "pe_analyze",
		"path":   txtPath,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	isPE, _ := out["is_pe"].(bool)
	if isPE {
		t.Error("expected is_pe=false for text file")
	}
}

func TestPEAnalyze_MissingPath(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	out, err := a.Execute(ctx, map[string]any{
		"action": "pe_analyze",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	errStr, _ := out["error"].(string)
	if errStr == "" {
		t.Error("expected error for missing path")
	}
}

func TestUnknownAction(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	_, err := a.Execute(ctx, map[string]any{
		"action": "nonexistent_action",
	})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestVTLookup_NoAPI(t *testing.T) {
	db := testDB(t)
	a := New(db, "")
	ctx := context.Background()

	out, err := a.Execute(ctx, map[string]any{
		"action":    "vt_lookup",
		"indicator": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	errStr, _ := out["error"].(string)
	if errStr == "" {
		t.Error("expected VT not configured error")
	}
}

func TestHashLengthClassification(t *testing.T) {
	tests := []struct {
		hash string
		len  int
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", 32},
		{"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", 40},
		{"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", 64},
	}
	for _, tt := range tests {
		t.Run(tt.hash[:8], func(t *testing.T) {
			if len(tt.hash) != tt.len {
				t.Errorf("len(%q) = %d, want %d", tt.hash, len(tt.hash), tt.len)
			}
		})
	}
}
