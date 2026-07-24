package batch

import (
	"context"
	"log"
	"sync"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// WriterGoroutine is a dedicated goroutine that owns a single storage.Writer
// connection. N producer goroutines feed batches into a channel, and the
// WriterGoroutine serializes writes through a single connection, removing
// writer-lock contention entirely.
type WriterGoroutine struct {
	ch      chan writeRequest
	writer  storage.Writer
	wg      sync.WaitGroup
	done    chan struct{}
	errOnce sync.Once
	err     error
}

type writeRequest struct {
	ctx  context.Context
	batch []*storage.Event
	errCh chan error
}

// NewWriterGoroutine starts a dedicated writer goroutine.
// It owns the provided writer and serializes all writes through it.
func NewWriterGoroutine(ctx context.Context, writer storage.Writer, queueDepth int) *WriterGoroutine {
	if queueDepth <= 0 {
		queueDepth = 100
	}

	w := &WriterGoroutine{
		ch:     make(chan writeRequest, queueDepth),
		writer: writer,
		done:   make(chan struct{}),
	}

	w.wg.Add(1)
	go w.loop(ctx)

	return w
}

// Submit sends a batch to the writer goroutine and waits for the result.
// It blocks until the batch has been written or the context is cancelled.
func (w *WriterGoroutine) Submit(ctx context.Context, batch []*storage.Event) error {
	req := writeRequest{
		ctx:   ctx,
		batch: batch,
		errCh: make(chan error, 1),
	}

	select {
	case w.ch <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return w.Err()
	}

	select {
	case err := <-req.errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return w.Err()
	}
}

// Err returns any fatal error that terminated the writer goroutine.
func (w *WriterGoroutine) Err() error {
	w.errOnce.Do(func() {})
	return w.err
}

// Close shuts down the writer goroutine and the underlying writer.
func (w *WriterGoroutine) Close() error {
	close(w.ch)
	w.wg.Wait()
	close(w.done)
	return w.writer.Close()
}

func (w *WriterGoroutine) loop(ctx context.Context) {
	defer w.wg.Done()

	for req := range w.ch {
		err := w.writer.WriteBatch(req.ctx, req.batch)
		req.errCh <- err
		if err != nil {
			w.errOnce.Do(func() {
				w.err = err
			})
			log.Printf("[tse] writer goroutine error: %v", err)
		}
	}

	// Drain remaining requests on shutdown
	for req := range w.ch {
		select {
		case req.errCh <- w.Err():
		default:
		}
	}
}
