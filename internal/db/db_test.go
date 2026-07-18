package db_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/db"
)

func TestOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer d.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("db file was not created")
	}
}

func TestMigrateCreatesTables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer d.Close()

	tables := []string{"investigations", "tasks", "results", "cache", "config", "events", "alerts"}
	for _, name := range tables {
		var count int
		err := d.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&count)
		if err != nil {
			t.Fatalf("query table %s: %v", name, err)
		}
		if count == 0 {
			t.Errorf("table %s not found after migration", name)
		}
	}
}

func TestMigrateIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	d1, err := db.Open(path)
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}
	d1.Close()

	d2, err := db.Open(path)
	if err != nil {
		t.Fatalf("second Open failed: %v", err)
	}
	d2.Close()
}
