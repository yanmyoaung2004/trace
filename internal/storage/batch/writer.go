package batch

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
)

// maxFlushAttempts bounds in-memory retries before DLQ-drop (R7).
const maxFlushAttempts = 5

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
	attempts     int
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
// Bounded attempts (R7): a failing batch is retried in-memory up to
// maxAttempts; afterwards it is moved to the DLQ drop counter path (logged
// with size) instead of re-prepending forever and head-of-line blocking the
// stream. Poison rows should be quarantined by the sink via DLQ; the writer
// guarantees the stream keeps moving.
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
		w.mu.Lock()
		w.attempts++
		n := w.attempts
		w.mu.Unlock()
		if n >= maxFlushAttempts {
			w.mu.Lock()
			w.attempts = 0
			w.mu.Unlock()
			log.Printf("[tse] batch DLQ: dropping %d events after %d attempts: %v", len(batch), n, err)
			metrics.Global.EventsDropped.Add(uint64(len(batch)))
		} else {
			// Re-queue failed events (push them back to the front)
			w.mu.Lock()
			w.batch = append(batch, w.batch...)
			w.mu.Unlock()
		}
	} else {
		w.mu.Lock()
		w.attempts = 0
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
