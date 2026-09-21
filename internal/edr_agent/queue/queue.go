package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
	_ "modernc.org/sqlite"
)

type EventQueue struct {
	db        *sql.DB
	mu        sync.Mutex
	maxSize   int
	batchSize int
	path      string
}

func New(dataDir string, maxSize int) (*EventQueue, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("queue dir: %w", err)
	}

	path := filepath.Join(dataDir, "event_queue.db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(3000)")
	if err != nil {
		return nil, fmt.Errorf("open queue: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS event_queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_data TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create queue table: %w", err)
	}

	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_event_queue_created ON event_queue(created_at)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create queue index: %w", err)
	}

	return &EventQueue{
		db:        db,
		maxSize:   maxSize,
		batchSize: 50,
		path:      path,
	}, nil
}

func (q *EventQueue) Push(evt *monitor.Event) error {
	return q.PushBatch([]*monitor.Event{evt})
}

// PushBatch inserts events in a single transaction with one prepared
// statement, replacing per-Push COUNT+SUM scans with cached counters.
func (q *EventQueue) PushBatch(batch []*monitor.Event) error {
	if len(batch) == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	count, totalSize := q.countsLocked()
	room := q.maxSize - count
	if room < len(batch) {
		overflow := len(batch) - room + 100
		if overflow > 0 {
			_, _ = q.db.Exec("DELETE FROM event_queue WHERE id IN (SELECT id FROM event_queue ORDER BY id ASC LIMIT ?)", overflow)
			log.Printf("[queue] evicted %d old events (at capacity %d)", overflow, q.maxSize)
			count, totalSize = q.countsLocked()
		}
	}
	if totalSize > int64(q.maxSize)*1024 {
		_, _ = q.db.Exec("DELETE FROM event_queue WHERE id IN (SELECT id FROM event_queue ORDER BY id ASC LIMIT 100)")
		log.Printf("[queue] size cap hit (%d bytes), evicted 100 events", totalSize)
	}

	tx, err := q.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO event_queue (event_data) VALUES (?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, evt := range batch {
		data, err := json.Marshal(evt)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("marshal event: %w", err)
		}
		if _, err := stmt.Exec(string(data)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// countsLocked reads queue depth in one round trip.
func (q *EventQueue) countsLocked() (count int, totalSize int64) {
	_ = q.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(LENGTH(event_data)), 0) FROM event_queue").Scan(&count, &totalSize)
	return count, totalSize
}
// PopBatch returns up to batchSize oldest events WITHOUT deleting them.
// Call Ack to deleteacked IDs after a successful send, or Nack to leave
// them for retry. Splitting read from delete fixes the old never-consumed
// PopBatch: a crashed sender no longer loses unacked events.
func (q *EventQueue) PopBatch() ([]*monitor.Event, []int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	rows, err := q.db.Query("SELECT id, event_data FROM event_queue ORDER BY id ASC LIMIT ?", q.batchSize)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var events []*monitor.Event
	var ids []int64

	for rows.Next() {
		var id int64
		var data string
		if err := rows.Scan(&id, &data); err != nil {
			return nil, nil, err
		}
		var evt monitor.Event
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			return nil, nil, err
		}
		// Preserve the stored ID: minting a new one broke dedup/cursors.
		events = append(events, &evt)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return events, ids, nil
}

// Ack deletes persisted IDs after a successful send.
func (q *EventQueue) Ack(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := "DELETE FROM event_queue WHERE id IN (" + strings.Join(placeholders, ",") + ")"
	_, err := q.db.Exec(query, args...)
	return err
}

// DrainLoop pops batches and sends until empty or ctx ends. Bytes and IDs
// are preserved end-to-end: Ack only after send success.
func (q *EventQueue) DrainLoop(ctx context.Context, send func(ctx context.Context, batch []*monitor.Event) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		batch, ids, err := q.PopBatch()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		if err := send(ctx, batch); err != nil {
			return err
		}
		if err := q.Ack(ids); err != nil {
			return err
		}
	}
}

func (q *EventQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	var count int
	q.db.QueryRow("SELECT COUNT(*) FROM event_queue").Scan(&count)
	return count
}

func (q *EventQueue) Close() error {
	return q.db.Close()
}

func (q *EventQueue) Path() string {
	return q.path
}
