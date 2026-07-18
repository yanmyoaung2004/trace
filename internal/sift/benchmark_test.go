package sift

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func benchDB(b *testing.B) *sql.DB {
	b.Helper()
	dir := b.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "bench.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(100)")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })
	db.Exec(`CREATE TABLE IF NOT EXISTS cache (
		key TEXT PRIMARY KEY, value TEXT NOT NULL,
		ttl INTEGER NOT NULL DEFAULT 3600, created_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`)
	return db
}

func BenchmarkYaraScan_EICAR(b *testing.B) {
	db := benchDB(b)
	a := New(db, "")
	ctx := context.Background()

	tmpDir := b.TempDir()
	eicarPath := filepath.Join(tmpDir, "eicar.txt")
	os.WriteFile(eicarPath, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Execute(ctx, map[string]any{
			"action": "yara_scan",
			"path":   eicarPath,
		})
	}
}

func BenchmarkYaraScan_CleanFile(b *testing.B) {
	db := benchDB(b)
	a := New(db, "")
	ctx := context.Background()

	tmpDir := b.TempDir()
	cleanPath := filepath.Join(tmpDir, "clean.txt")
	os.WriteFile(cleanPath, []byte("Hello, world! This is a clean file."), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Execute(ctx, map[string]any{
			"action": "yara_scan",
			"path":   cleanPath,
		})
	}
}

func BenchmarkHashLookup_Known(b *testing.B) {
	db := benchDB(b)
	a := New(db, "")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Execute(ctx, map[string]any{
			"action": "hash_lookup",
			"hash":   "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		})
	}
}

func BenchmarkHashLookup_Unknown(b *testing.B) {
	db := benchDB(b)
	a := New(db, "")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Execute(ctx, map[string]any{
			"action": "hash_lookup",
			"hash":   "0000000000000000000000000000000000000000000000000000000000000000",
		})
	}
}

func BenchmarkPEAnalyze_NotPE(b *testing.B) {
	db := benchDB(b)
	a := New(db, "")
	ctx := context.Background()

	tmpDir := b.TempDir()
	txtPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(txtPath, []byte("not a PE file"), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Execute(ctx, map[string]any{
			"action": "pe_analyze",
			"path":   txtPath,
		})
	}
}
