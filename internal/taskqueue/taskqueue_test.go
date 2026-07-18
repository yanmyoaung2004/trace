package taskqueue_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/db"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/taskqueue"
)

func setupQueue(t *testing.T) *taskqueue.Queue {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return taskqueue.New(database)
}

func TestEnqueue(t *testing.T) {
	q := setupQueue(t)
	ctx := context.Background()

	task, err := q.Enqueue(ctx, "inv-1", "detection", "hash_lookup", map[string]any{"hash": "abc123"})
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	if task.ID == "" {
		t.Fatal("task ID should not be empty")
	}
	if task.Status != "pending" {
		t.Fatalf("expected status pending, got %s", task.Status)
	}
}

func TestClaim(t *testing.T) {
	q := setupQueue(t)
	ctx := context.Background()

	_, err := q.Enqueue(ctx, "inv-1", "detection", "hash_lookup", map[string]any{"hash": "abc"})
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	task, err := q.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim failed: %v", err)
	}
	if task == nil {
		t.Fatal("expected task, got nil")
	}
	if task.Status != "running" {
		t.Fatalf("expected status running, got %s", task.Status)
	}

	claimed, err := q.Claim(ctx)
	if err != nil {
		t.Fatalf("second Claim failed: %v", err)
	}
	if claimed != nil {
		t.Fatal("should not claim same task twice")
	}
}

func TestComplete(t *testing.T) {
	q := setupQueue(t)
	ctx := context.Background()

	task, err := q.Enqueue(ctx, "inv-1", "detection", "hash_lookup", map[string]any{})
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	_, err = q.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim failed: %v", err)
	}

	err = q.Complete(ctx, task.ID, map[string]any{"reputation": "malicious"})
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
}

func TestFail(t *testing.T) {
	q := setupQueue(t)
	ctx := context.Background()

	task, err := q.Enqueue(ctx, "inv-1", "detection", "hash_lookup", map[string]any{})
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	_, err = q.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim failed: %v", err)
	}

	err = q.Fail(ctx, task.ID, "something went wrong")
	if err != nil {
		t.Fatalf("Fail failed: %v", err)
	}
}

func TestClaimReturnsOldestFirst(t *testing.T) {
	q := setupQueue(t)
	ctx := context.Background()

	q.Enqueue(ctx, "inv-1", "detection", "a", map[string]any{})
	q.Enqueue(ctx, "inv-2", "detection", "b", map[string]any{})

	t1, _ := q.Claim(ctx)
	t2, _ := q.Claim(ctx)

	if t1.Action != "a" {
		t.Fatalf("expected first enqueued, got %s", t1.Action)
	}
	if t2.Action != "b" {
		t.Fatalf("expected second enqueued, got %s", t2.Action)
	}
}
