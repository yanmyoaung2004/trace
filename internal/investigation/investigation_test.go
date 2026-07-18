package investigation_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/db"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/investigation"
)

func setupManager(t *testing.T) *investigation.Manager {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return investigation.NewManager(database)
}

func TestCreate(t *testing.T) {
	mgr := setupManager(t)
	ctx := context.Background()

	inv, err := mgr.Create(ctx, "check this file", "file-analysis")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if inv.ID == "" {
		t.Fatal("investigation ID should not be empty")
	}
	if inv.Status != "pending" {
		t.Fatalf("expected status pending, got %s", inv.Status)
	}
	if inv.Intent != "check this file" {
		t.Fatalf("unexpected intent: %s", inv.Intent)
	}
}

func TestGet(t *testing.T) {
	mgr := setupManager(t)
	ctx := context.Background()

	created, err := mgr.Create(ctx, "test intent", "test-playbook")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	fetched, err := mgr.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if fetched.ID != created.ID {
		t.Fatalf("ID mismatch: %s vs %s", fetched.ID, created.ID)
	}
	if fetched.Intent != "test intent" {
		t.Fatalf("intent mismatch: %s", fetched.Intent)
	}
}

func TestUpdateStatus(t *testing.T) {
	mgr := setupManager(t)
	ctx := context.Background()

	inv, err := mgr.Create(ctx, "test", "test")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := mgr.UpdateStatus(ctx, inv.ID, "running"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	fetched, _ := mgr.Get(ctx, inv.ID)
	if fetched.Status != "running" {
		t.Fatalf("expected running, got %s", fetched.Status)
	}
}

func TestLogWriter(t *testing.T) {
	dir := t.TempDir()

	lw, err := investigation.NewLogWriter(dir)
	if err != nil {
		t.Fatalf("NewLogWriter failed: %v", err)
	}

	if err := lw.WriteEvent("inv-1", "intent", map[string]string{"query": "check file"}); err != nil {
		t.Fatalf("WriteEvent failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "inv-1.jsonl"))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("log file is empty")
	}
}

func TestLogWriterAppends(t *testing.T) {
	dir := t.TempDir()

	lw, _ := investigation.NewLogWriter(dir)
	lw.WriteEvent("inv-1", "first", "data1")
	lw.WriteEvent("inv-1", "second", "data2")

	data, _ := os.ReadFile(filepath.Join(dir, "inv-1.jsonl"))
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Fatalf("expected 2 lines, got %d", lines)
	}
}
