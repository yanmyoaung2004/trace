package storage_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/batch"
	"github.com/yanmyoaung2004/trace/internal/storage/queue"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

func TestQueueBatchWriterPipeline(t *testing.T) {
	dir, err := os.MkdirTemp("", "pipeline-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create SQLiteHotStore
	dbPath := filepath.Join(dir, "tse.db")
	hot, err := sqlite.NewSQLiteHotStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer hot.Close()

	// Create queue
	q, err := queue.NewIngestQueue(queue.DefaultQueueCapacity, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create batch writer
	bw := batch.NewBatchWriter(10, 50*time.Millisecond)

	// Wire: queue → batch writer → SQLite
	go bw.Run(ctx, q.Dequeue(), hot.WriteBatch)

	// Write events through the queue
	events := make([]*storage.Event, 5)
	for i := range events {
		events[i] = &storage.Event{
			ID:        idFromInt(i),
			TenantID:  "test",
			AgentID:   "pipeline",
			Timestamp: time.Now().UnixMicro(),
			EventType: "test:queue",
			Severity:  i + 1,
			Hostname:  "host-a",
		}
	}

	if err := q.WriteBatch(ctx, events); err != nil {
		t.Fatal(err)
	}

	// Give batch writer time to flush
	time.Sleep(200 * time.Millisecond)

	// Verify events are in SQLite
	got, err := hot.Query(ctx, storage.Query{
		TenantID: "test",
		Limit:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != len(events) {
		t.Fatalf("got %d events, want %d", len(got.Events), len(events))
	}
}

func TestQueueBatchWriterBackpressure(t *testing.T) {
	dir, err := os.MkdirTemp("", "pipeline-backpressure-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPath := filepath.Join(dir, "tse.db")
	hot, err := sqlite.NewSQLiteHotStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer hot.Close()

	// Small queue capacity (no disk spill) to force drops
	q, err := queue.NewIngestQueue(1, nil)
	if err != nil {
		t.Fatal(err)
	}

	bw := batch.NewBatchWriter(10, 50*time.Millisecond)
	go bw.Run(ctx, q.Dequeue(), hot.WriteBatch)

	// Write more events than queue can hold
	events := make([]*storage.Event, 100)
	for i := range events {
		events[i] = &storage.Event{
			ID:        idFromInt(i),
			TenantID:  "test",
			AgentID:   "backpressure",
			Timestamp: time.Now().UnixMicro(),
			EventType: "test:backpressure",
			Severity:  i,
			Hostname:  "host-a",
		}
	}

	// Batch write — queue should accept and buffer
	if err := q.WriteBatch(ctx, events); err != nil {
		t.Logf("expected possible drop, got err: %v", err)
	}

	// Give batch writer time to drain
	time.Sleep(500 * time.Millisecond)

	// At least some events should be written
	got, err := hot.Query(ctx, storage.Query{
		TenantID: "test",
		Limit:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) == 0 {
		t.Fatal("expected at least some events to survive backpressure")
	}
	t.Logf("survived backpressure: %d/%d events", len(got.Events), len(events))
}

func idFromInt(i int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
}
