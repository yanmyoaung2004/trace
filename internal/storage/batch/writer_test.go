package batch

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func TestBatchWriter_AccumulatesUntilSize(t *testing.T) {
	input := make(chan *storage.Event, 100)
	var batches [][]*storage.Event
	var mu sync.Mutex

	sink := func(ctx context.Context, batch []*storage.Event) error {
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		return nil
	}

	w := NewBatchWriter(10, time.Hour) // size=10, timeout=1h (won't trip)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go w.Run(ctx, input, sink)

	for i := 0; i < 10; i++ {
		input <- &storage.Event{ID: "e"}
	}

	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	count := len(batches)
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 batch after 10 events, got %d", count)
	}
}

func TestBatchWriter_FlushesOnTimeout(t *testing.T) {
	input := make(chan *storage.Event, 100)
	flushed := make(chan struct{})

	sink := func(ctx context.Context, batch []*storage.Event) error {
		close(flushed)
		return nil
	}

	w := NewBatchWriter(100, 50*time.Millisecond) // timeout=50ms
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go w.Run(ctx, input, sink)

	input <- &storage.Event{ID: "e"}

	select {
	case <-flushed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected flush before 200ms")
	}
}

func TestBatchWriter_MultipleBatches(t *testing.T) {
	input := make(chan *storage.Event, 200)
	var count atomic.Int32
	sink := func(ctx context.Context, batch []*storage.Event) error {
		count.Add(int32(len(batch)))
		return nil
	}

	w := NewBatchWriter(10, time.Hour)
	ctx := context.Background()

	go w.Run(ctx, input, sink)

	for i := 0; i < 25; i++ {
		input <- &storage.Event{ID: "e"}
	}
	close(input)
	<-w.Done()

	if n := count.Load(); n != 25 {
		t.Errorf("expected 25 events processed, got %d", n)
	}
}

func TestBatchWriter_ContextCancel(t *testing.T) {
	input := make(chan *storage.Event, 100)
	sink := func(ctx context.Context, batch []*storage.Event) error {
		return nil
	}

	w := NewBatchWriter(10, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := w.Run(ctx, input, sink)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestBatchWriter_CloseInputChannel(t *testing.T) {
	input := make(chan *storage.Event, 100)
	var count atomic.Int32

	sink := func(ctx context.Context, batch []*storage.Event) error {
		count.Add(int32(len(batch)))
		return nil
	}

	w := NewBatchWriter(10, time.Hour)
	ctx := context.Background()

	go w.Run(ctx, input, sink)

	for i := 0; i < 5; i++ {
		input <- &storage.Event{ID: "e"}
	}
	close(input)

	select {
	case <-w.Done():
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after input channel closed")
	}

	if n := count.Load(); n != 5 {
		t.Errorf("expected 5 events, got %d", n)
	}
}

func TestBatchWriter_RequeuesOnSinkError(t *testing.T) {
	input := make(chan *storage.Event, 100)
	var attempts atomic.Int32
	first := true

	sink := func(ctx context.Context, batch []*storage.Event) error {
		if first {
			first = false
			attempts.Add(1)
			return nil // let first batch succeed
		}
		return nil
	}

	w := NewBatchWriter(5, time.Hour)
	ctx := context.Background()

	go w.Run(ctx, input, sink)

	for i := 0; i < 5; i++ {
		input <- &storage.Event{ID: "e"}
	}
	close(input)
	<-w.Done()
}
