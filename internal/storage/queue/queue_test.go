package queue

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func TestIngestQueue_EnqueueDequeue(t *testing.T) {
	q, err := NewIngestQueue(100, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	evt := &storage.Event{ID: "test-1"}
	if err := q.Enqueue(context.Background(), evt); err != nil {
		t.Fatal(err)
	}

	select {
	case received := <-q.Dequeue():
		if received.ID != "test-1" {
			t.Errorf("expected test-1, got %s", received.ID)
		}
	default:
		t.Fatal("expected event on dequeue channel")
	}
}

func TestIngestQueue_BlockOnFull(t *testing.T) {
	q, err := NewIngestQueue(1, nil) // capacity 1
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Fill the queue
	q.Enqueue(context.Background(), &storage.Event{ID: "fill"})

	// Second enqueue should timeout and return ErrEventDropped
	err = q.Enqueue(context.Background(), &storage.Event{ID: "overflow"})
	if err != ErrEventDropped {
		t.Errorf("expected ErrEventDropped, got %v", err)
	}

	if q.Dropped() != 1 {
		t.Errorf("expected 1 dropped, got %d", q.Dropped())
	}
}

func TestIngestQueue_SpillAndDrain(t *testing.T) {
	dir := t.TempDir()
	q, err := NewIngestQueue(1, &DiskSpillConfig{Dir: dir, Limit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Fill queue
	q.Enqueue(context.Background(), &storage.Event{ID: "fill"})

	// Overflow to spill
	if err := q.Enqueue(context.Background(), &storage.Event{ID: "spilled"}); err != nil {
		t.Errorf("expected spill to succeed, got %v", err)
	}

	if q.Dropped() != 0 {
		t.Errorf("expected 0 dropped with spill, got %d", q.Dropped())
	}
}

func TestIngestQueue_Concurrent(t *testing.T) {
	q, err := NewIngestQueue(10000, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	var wg sync.WaitGroup
	n := 1000

	// Producer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			q.Enqueue(context.Background(), &storage.Event{ID: "e"})
		}
	}()

	// Consumer
	go func() {
		for range q.Dequeue() {
		}
	}()

	wg.Wait()
	time.Sleep(10 * time.Millisecond)
	q.Close()

	if dropped := q.Dropped(); dropped > 0 {
		t.Errorf("expected 0 dropped, got %d", dropped)
	}
}

func TestDiskSpill_WriteLimit(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskSpill(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Write enough to exceed limit
	for i := 0; i < 100; i++ {
		s.Write(&storage.Event{ID: "e"})
	}

	if s.total < 100 {
		t.Errorf("expected total >= 100, got %d", s.total)
	}
}

func TestDiskSpill_Replay(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskSpill(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	s.Write(&storage.Event{ID: "replay-1"})
	s.Write(&storage.Event{ID: "replay-2"})

	var count atomic.Int32
	ctx := context.Background()
	if err := s.Replay(ctx, func(e *storage.Event) error {
		count.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if count.Load() != 2 {
		t.Errorf("expected 2 replayed events, got %d", count.Load())
	}

	s.Close()
	// Verify segments are cleaned up
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected 0 files after replay, got %d", len(entries))
	}
}

func TestIngestQueue_Close(t *testing.T) {
	dir := t.TempDir()
	q, err := NewIngestQueue(10, &DiskSpillConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}

	q.Close()

	// Enqueue after close should fail
	err = q.Enqueue(context.Background(), &storage.Event{ID: "after-close"})
	if err != ErrQueueClosed {
		t.Errorf("expected ErrQueueClosed, got %v", err)
	}
}

func TestIngestQueue_ContextCancel(t *testing.T) {
	q, err := NewIngestQueue(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	q.Enqueue(context.Background(), &storage.Event{ID: "fill"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = q.Enqueue(ctx, &storage.Event{ID: "canceled"})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func BenchmarkIngestQueue_Enqueue(b *testing.B) {
	q, _ := NewIngestQueue(65536, nil)
	defer q.Close()

	evt := &storage.Event{ID: "bench"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Enqueue(ctx, evt)
	}
}

func BenchmarkIngestQueue_Throughput(b *testing.B) {
	q, _ := NewIngestQueue(65536, nil)
	defer q.Close()

	// Consumer
	go func() {
		for range q.Dequeue() {
		}
	}()

	evt := &storage.Event{ID: "bench"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Enqueue(ctx, evt)
	}
}

func TestDiskSpill_NonExistentDir(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(dir, "subdir")
	_, err := NewDiskSpill(d, 0)
	if err != nil {
		t.Fatal(err)
	}
}
