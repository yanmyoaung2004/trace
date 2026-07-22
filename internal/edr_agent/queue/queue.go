package queue

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
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
	q.mu.Lock()
	defer q.mu.Unlock()

	// Check size
	var count int
	q.db.QueryRow("SELECT COUNT(*) FROM event_queue").Scan(&count)
	if count >= q.maxSize {
		q.db.Exec("DELETE FROM event_queue WHERE id IN (SELECT id FROM event_queue ORDER BY id ASC LIMIT ?)", count-q.maxSize+100)
	}

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	_, err = q.db.Exec("INSERT INTO event_queue (event_data) VALUES (?)", string(data))
	return err
}

func (q *EventQueue) PopBatch() ([]*monitor.Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	rows, err := q.db.Query("SELECT id, event_data FROM event_queue ORDER BY id ASC LIMIT ?", q.batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type entry struct {
		id   int64
		data string
	}
	var entries []entry

	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.data); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Delete the entries we just read
	ids := make([]any, len(entries))
	events := make([]*monitor.Event, 0, len(entries))
	for i, e := range entries {
		ids[i] = e.id
		var evt monitor.Event
		if err := json.Unmarshal([]byte(e.data), &evt); err != nil {
			continue
		}
		// Regenerate ID to avoid duplicates
		if evt.ID == "" {
			evt.ID = uuid.New().String()
		}
		events = append(events, &evt)
	}

	if len(ids) > 0 {
		placeholders := make([]string, len(ids))
		for i := range placeholders {
			placeholders[i] = "?"
		}
		query := "DELETE FROM event_queue WHERE id IN (" + strings.Join(placeholders, ",") + ")"
		q.db.Exec(query, ids...)
	}

	return events, nil
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
