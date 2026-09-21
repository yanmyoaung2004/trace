package queue

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
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

// OnDropFunc is called when an event is dropped (for metrics hookup).
type OnDropFunc func()

// IngestQueue is a bounded MPMC queue with backpressure:
// 1. Block briefly (channel send with timeout)
// 2. Spill to disk (append-only segment files storing FULL events)
// 3. Drop with counter and alert (absolute last resort)
type IngestQueue struct {
	ch        chan *storage.Event
	spill     *DiskSpill
	timeout   time.Duration
	dropped   atomic.Uint64
	closeOnce sync.Once
	closeCh   chan struct{}
	onDrop    OnDropFunc
}

// OnDrop registers a callback for dropped events.
func (q *IngestQueue) OnDrop(fn OnDropFunc) {
	q.onDrop = fn
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
				if q.onDrop != nil {
					q.onDrop()
				}
				return ErrEventDropped
			}
			return nil
		}
		q.dropped.Add(1)
		if q.onDrop != nil {
			q.onDrop()
		}
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

// DiskSpill stores overflow events to disk as append-only segment files.
// Each segment holds a JSON-lines sequence of FULL events (P-H5 fix: the old
// one-file-per-event spill stored only the ID and was lossy + IOPS-heavy).
type DiskSpill struct {
	dir      string
	limit    int64
	mu       sync.Mutex
	segments []string
	cur      *os.File
	curSize  int64
	total    int64
}

// segmentMaxBytes caps a single spill segment before rotation.
const segmentMaxBytes = 16 << 20

// NewDiskSpill creates a disk spill directory.
func NewDiskSpill(dir string, limit int64) (*DiskSpill, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("spill dir: %w", err)
	}
	return &DiskSpill{dir: dir, limit: limit}, nil
}

// Write appends a full event to the current spill segment (fsync per write
// keeps crash recovery simple; segment rotation bounds file size).
func (s *DiskSpill) Write(e *storage.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("spill marshal: %w", err)
	}
	data = append(data, '\n')
	if s.limit > 0 && s.total+int64(len(data)) > s.limit {
		return fmt.Errorf("spill full (%d/%d bytes)", s.total, s.limit)
	}
	if s.cur == nil || s.curSize >= segmentMaxBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := s.cur.Write(data); err != nil {
		return fmt.Errorf("spill write: %w", err)
	}
	if err := s.cur.Sync(); err != nil {
		return fmt.Errorf("spill fsync: %w", err)
	}
	s.curSize += int64(len(data))
	s.total += int64(len(data))
	return nil
}

// rotateLocked closes the current segment and opens a new one (O_EXCL, 0600).
func (s *DiskSpill) rotateLocked() error {
	if s.cur != nil {
		s.cur.Close()
		s.cur = nil
	}
	name := filepath.Join(s.dir, "spill-"+uuid.New().String()+".log")
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("spill create: %w", err)
	}
	s.cur = f
	s.curSize = 0
	s.segments = append(s.segments, name)
	return nil
}

// Replay reads all spilled segments and re-injects full events into the queue.
func (s *DiskSpill) Replay(ctx context.Context, inject func(*storage.Event) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.cur.Close()
		s.cur = nil
	}

	for _, seg := range s.segments {
		if err := s.replaySegment(ctx, seg, inject); err != nil {
			return err
		}
		os.Remove(seg)
	}
	s.segments = nil
	s.total = 0
	return nil
}

// replaySegment streams one JSON-lines segment without holding unbounded RAM.
func (s *DiskSpill) replaySegment(ctx context.Context, seg string, inject func(*storage.Event) error) error {
	f, err := os.Open(seg)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("spill replay: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var evt storage.Event
		if err := json.Unmarshal(sc.Bytes(), &evt); err != nil {
			continue // skip corrupt line, keep draining
		}
		e := evt
		if err := inject(&e); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Close cleans up all spill segments.
func (s *DiskSpill) Close() error {
	s.mu.Lock()
	if s.cur != nil {
		s.cur.Close()
		s.cur = nil
	}
	var lastErr error
	for _, seg := range s.segments {
		if err := os.Remove(seg); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	s.segments = nil
	s.total = 0
	s.curSize = 0
	return lastErr
}

// Ensure IngestQueue implements storage.Writer.
var _ storage.Writer = (*IngestQueue)(nil)

// WriteBatch implements storage.Writer by sending events through the queue.
// This allows the queue to be used as the ingest entry point.
// W4: the 95% disk-full gate is enforced here (before memory/spill admit, so
// a full volume cannot be papered over by buffering), while the hot-store
// WriteBatch re-checks at commit depth for direct writers that bypass the
// queue. Rejections increment metrics.Global.DiskFullRejected. Warn at 85%
// logs at most once per minute via storage.LogDiskWarn.
func (q *IngestQueue) WriteBatch(ctx context.Context, events []*storage.Event) error {
	if len(events) == 0 {
		return nil
	}
	if storage.StoragePathFunc != nil {
		if du, err := storage.GetDiskUsage(storage.StoragePathFunc()); err == nil {
			if storage.IsDiskFull(du) {
				metrics.Global.DiskFullRejected.Add(1)
				return storage.ErrDiskFull
			}
			storage.LogDiskWarn(du)
		}
	}
	for _, e := range events {
		if err := q.Enqueue(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// Ensure DiskSpill implements io.Closer.
var _ io.Closer = (*DiskSpill)(nil)
