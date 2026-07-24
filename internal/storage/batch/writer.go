package batch

import (
	"context"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// BatchWriter accumulates events into batches and flushes them via a sink function.
// It implements the core batching pattern: accumulate N events OR wait M duration,
// then call the sink with the complete batch.
type BatchWriter struct {
	batchSize    int
	batchTimeout time.Duration
	mu           sync.Mutex
	batch        []*storage.Event
	flushTimer   *time.Timer
	flushing     bool
	done         chan struct{}
}

// NewBatchWriter creates a batch writer with the given target batch size and timeout.
// The sink is called on every flush with the accumulated events.
func NewBatchWriter(batchSize int, batchTimeout time.Duration) *BatchWriter {
	if batchSize <= 0 {
		batchSize = 1000
	}
	if batchTimeout <= 0 {
		batchTimeout = 250 * time.Millisecond
	}
	return &BatchWriter{
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
		batch:        make([]*storage.Event, 0, batchSize),
		done:         make(chan struct{}),
	}
}

// Run starts the batch writer loop. It reads from the input channel, accumulates
// events, and calls sink with each completed batch. The sink is responsible for
// writing the batch to storage (SQLite, etc.).
//
// Run blocks until the context is cancelled or the input channel is closed.
func (w *BatchWriter) Run(ctx context.Context, input <-chan *storage.Event, sink func(context.Context, []*storage.Event) error) error {
	defer close(w.done)

	w.mu.Lock()
	w.flushTimer = time.NewTimer(w.batchTimeout)
	if !w.flushTimer.Stop() {
		<-w.flushTimer.C
	}
	w.flushTimer.Reset(w.batchTimeout)
	w.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			w.flush(ctx, sink)
			return ctx.Err()

		case evt, ok := <-input:
			if !ok {
				w.flush(ctx, sink)
				return nil
			}

			w.mu.Lock()
			w.batch = append(w.batch, evt)
			shouldFlush := len(w.batch) >= w.batchSize
			w.mu.Unlock()

			if shouldFlush {
				w.flush(ctx, sink)
			}

		case <-w.flushTimer.C:
			w.flush(ctx, sink)
			w.mu.Lock()
			if !w.flushing {
				w.flushTimer.Reset(w.batchTimeout)
			}
			w.mu.Unlock()
		}
	}
}

// flush sends the current batch to the sink and resets accumulation.
func (w *BatchWriter) flush(ctx context.Context, sink func(context.Context, []*storage.Event) error) {
	w.mu.Lock()
	if len(w.batch) == 0 {
		w.mu.Unlock()
		return
	}
	if w.flushing {
		w.mu.Unlock()
		return
	}
	w.flushing = true
	batch := w.batch
	w.batch = make([]*storage.Event, 0, w.batchSize)
	w.mu.Unlock()

	// Reset the flush timer
	if err := sink(ctx, batch); err != nil {
		// Re-queue failed events (push them back to the front)
		w.mu.Lock()
		w.batch = append(batch, w.batch...)
		w.mu.Unlock()
	}

	w.mu.Lock()
	w.flushing = false
	w.flushTimer.Reset(w.batchTimeout)
	w.mu.Unlock()
}

// Done returns a channel that is closed when Run exits.
func (w *BatchWriter) Done() <-chan struct{} {
	return w.done
}

// Len returns the current number of events in the pending batch.
func (w *BatchWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.batch)
}
