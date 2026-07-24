package batch

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// mockWriter implements storage.Writer for testing.
type mockWriter struct {
	mu     sync.Mutex
	events []*storage.Event
	failOn int // fail after this many writes
	count  atomic.Int32
}

func (m *mockWriter) WriteBatch(ctx context.Context, events []*storage.Event) error {
	if m.failOn > 0 {
		n := m.count.Add(1)
		if int(n) >= m.failOn {
			return nil
		}
	}
	m.mu.Lock()
	m.events = append(m.events, events...)
	m.mu.Unlock()
	return nil
}

func (m *mockWriter) Close() error {
	return nil
}

func TestWriterGoroutine_SubmitsBatch(t *testing.T) {
	mw := &mockWriter{}
	w := NewWriterGoroutine(context.Background(), mw, 10)
	defer w.Close()

	err := w.Submit(context.Background(), []*storage.Event{{ID: "e1"}})
	if err != nil {
		t.Fatal(err)
	}

	mw.mu.Lock()
	if len(mw.events) != 1 {
		t.Errorf("expected 1 event, got %d", len(mw.events))
	}
	mw.mu.Unlock()
}

func TestWriterGoroutine_MultipleBatches(t *testing.T) {
	mw := &mockWriter{}
	w := NewWriterGoroutine(context.Background(), mw, 10)
	defer w.Close()

	for i := 0; i < 10; i++ {
		if err := w.Submit(context.Background(), []*storage.Event{{ID: "e"}}); err != nil {
			t.Fatal(err)
		}
	}

	mw.mu.Lock()
	if len(mw.events) != 10 {
		t.Errorf("expected 10 events, got %d", len(mw.events))
	}
	mw.mu.Unlock()
}

func TestWriterGoroutine_ConcurrentSubmissions(t *testing.T) {
	mw := &mockWriter{}
	w := NewWriterGoroutine(context.Background(), mw, 100)
	defer w.Close()

	var wg sync.WaitGroup
	n := 50

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Submit(context.Background(), []*storage.Event{{ID: "e"}})
		}()
	}

	wg.Wait()

	mw.mu.Lock()
	if len(mw.events) != n {
		t.Errorf("expected %d events, got %d", n, len(mw.events))
	}
	mw.mu.Unlock()
}

func TestWriterGoroutine_ContextCancelled(t *testing.T) {
	mw := &mockWriter{}
	w := NewWriterGoroutine(context.Background(), mw, 10)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := w.Submit(ctx, []*storage.Event{{ID: "e"}})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	w.Close()
}

func TestWriterGoroutine_CloseDrainsPending(t *testing.T) {
	mw := &mockWriter{}
	w := NewWriterGoroutine(context.Background(), mw, 10)

	// Submit a batch then close
	w.Submit(context.Background(), []*storage.Event{{ID: "e1"}})
	w.Close()

	// After close, new submissions should fail or be handled gracefully
	mw.mu.Lock()
	if len(mw.events) == 0 {
		t.Error("expected at least one event after close")
	}
	mw.mu.Unlock()
}
