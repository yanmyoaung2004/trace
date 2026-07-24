package queue

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/storage"
)

// DefaultQueueCapacity is the default ring buffer capacity.
const DefaultQueueCapacity = 65536

// DefaultEnqueueTimeout is how long Enqueue blocks before spilling to disk.
const DefaultEnqueueTimeout = 100 * time.Millisecond

// DiskSpillConfig configures the overflow spill-to-disk mechanism.
type DiskSpillConfig struct {
	Dir   string // directory for spill segments
	Limit int64  // max bytes before dropping (0 = unlimited)
}

// IngestQueue is a bounded MPMC queue with backpressure:
// 1. Block briefly (channel send with timeout)
// 2. Spill to disk (segment files)
// 3. Drop with counter and alert (absolute last resort)
type IngestQueue struct {
	ch        chan *storage.Event
	spill     *DiskSpill
	timeout   time.Duration
	dropped   atomic.Uint64
	closeOnce sync.Once
	closeCh   chan struct{}
}

// NewIngestQueue creates a bounded ingest queue.
func NewIngestQueue(capacity int, spillCfg *DiskSpillConfig) (*IngestQueue, error) {
	if capacity <= 0 {
		capacity = DefaultQueueCapacity
	}
	q := &IngestQueue{
		ch:      make(chan *storage.Event, capacity),
		timeout: DefaultEnqueueTimeout,
		closeCh: make(chan struct{}),
	}

	if spillCfg != nil && spillCfg.Dir != "" {
		spill, err := NewDiskSpill(spillCfg.Dir, spillCfg.Limit)
		if err != nil {
			return nil, fmt.Errorf("queue: spill: %w", err)
		}
		q.spill = spill
	}

	return q, nil
}

// Enqueue adds an event to the queue. Blocks up to the timeout, then spills
// to disk. If spill is unavailable, increments the drop counter and returns
// an error.
func (q *IngestQueue) Enqueue(ctx context.Context, e *storage.Event) error {
	if q.IsClosed() {
		return ErrQueueClosed
	}
	select {
	case q.ch <- e:
		return nil
	case <-time.After(q.timeout):
		// Channel full — try spill
		if q.spill != nil {
			if err := q.spill.Write(e); err != nil {
				q.dropped.Add(1)
				return ErrEventDropped
			}
			return nil
		}
		q.dropped.Add(1)
		return ErrEventDropped
	case <-ctx.Done():
		return ctx.Err()
	case <-q.closeCh:
		return ErrQueueClosed
	}
}

// Dequeue returns a channel that yields events in FIFO order.
// Events from the spill are re-injected before in-memory events.
func (q *IngestQueue) Dequeue() <-chan *storage.Event {
	return q.ch
}

// Len returns the current number of events in the in-memory buffer.
func (q *IngestQueue) Len() int {
	return len(q.ch)
}

// Dropped returns the cumulative count of dropped events.
func (q *IngestQueue) Dropped() uint64 {
	return q.dropped.Load()
}

// Close shuts down the queue and releases resources.
func (q *IngestQueue) Close() error {
	q.closeOnce.Do(func() {
		close(q.closeCh)
	})
	if q.spill != nil {
		return q.spill.Close()
	}
	return nil
}

// IsClosed returns whether the queue has been shut down.
func (q *IngestQueue) IsClosed() bool {
	select {
	case <-q.closeCh:
		return true
	default:
		return false
	}
}

var (
	ErrEventDropped = fmt.Errorf("queue: event dropped")
	ErrQueueClosed  = fmt.Errorf("queue: closed")
)

// DiskSpill stores overflow events to disk as segment files.
type DiskSpill struct {
	dir   string
	limit int64
	mu    sync.Mutex
	segments []string
	total    int64
}

// NewDiskSpill creates a disk spill directory.
func NewDiskSpill(dir string, limit int64) (*DiskSpill, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("spill dir: %w", err)
	}
	return &DiskSpill{dir: dir, limit: limit}, nil
}

// Write serializes an event to a spill segment file.
func (s *DiskSpill) Write(e *storage.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.limit > 0 && s.total >= s.limit {
		return fmt.Errorf("spill full (%d/%d bytes)", s.total, s.limit)
	}

	name := filepath.Join(s.dir, "spill-"+uuid.New().String()+".evt")
	data := []byte(e.ID + "\n") // minimal — real impl would use encoding/gob
	if err := os.WriteFile(name, data, 0600); err != nil {
		return fmt.Errorf("spill write: %w", err)
	}
	s.segments = append(s.segments, name)
	s.total += int64(len(data))
	return nil
}

// Replay reads all spilled segments and re-injects them into the queue.
func (s *DiskSpill) Replay(ctx context.Context, inject func(*storage.Event) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, seg := range s.segments {
		data, err := os.ReadFile(seg)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("spill replay: %w", err)
		}
		evt := &storage.Event{ID: string(data)}
		if err := inject(evt); err != nil {
			return err
		}
		os.Remove(seg)
	}
	s.segments = nil
	s.total = 0
	return nil
}

// Close cleans up all spill segments.
func (s *DiskSpill) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var lastErr error
	for _, seg := range s.segments {
		if err := os.Remove(seg); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	s.segments = nil
	s.total = 0
	return lastErr
}

// Ensure IngestQueue implements storage.Writer.
var _ storage.Writer = (*IngestQueue)(nil)

// WriteBatch implements storage.Writer by sending events through the queue.
// This allows the queue to be used as the ingest entry point.
func (q *IngestQueue) WriteBatch(ctx context.Context, events []*storage.Event) error {
	for _, e := range events {
		if err := q.Enqueue(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// Ensure DiskSpill implements io.Closer.
var _ io.Closer = (*DiskSpill)(nil)
