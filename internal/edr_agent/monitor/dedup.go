package monitor

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const batchMapMax = 500
const batchFlushThr = 375

type Deduplicator struct {
	mu        sync.Mutex
	mem       map[string]time.Time
	db        *sql.DB
	ttl       time.Duration
	maxMem    int
	hitCount  int64
	missCount int64
	batch     map[string]bool
	batchCh   chan struct{}
	done      chan struct{}
	dataDir   string
	batchFull chan struct{}
}

func NewDeduplicator(dataDir string) *Deduplicator {
	d := &Deduplicator{
		mem:       make(map[string]time.Time),
		batch:     make(map[string]bool),
		batchCh:   make(chan struct{}, 1),
		batchFull: make(chan struct{}, 1),
		done:      make(chan struct{}),
		ttl:       30 * time.Second,
		maxMem:    10000,
		dataDir:   dataDir,
	}
	if dataDir != "" {
		if err := d.openDB(dataDir); err != nil {
			log.Printf("[dedup] sqlite unavailable: %v (using memory only)", err)
		}
	}
	d.loadMem()
	go d.batchFlusher()
	return d
}

func (d *Deduplicator) batchFlusher() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[dedup] flusher panic: %v (restarting)", r)
			time.Sleep(time.Second)
			go d.batchFlusher()
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-d.done:
			d.flushBatch()
			return
		case <-tick.C:
			d.flushBatch()
		case <-d.batchCh:
			d.flushBatch()
		case <-d.batchFull:
			// Urgent flush: batch is at 75%+ capacity
			d.flushBatch()
			// If still >50% after flush, flush again immediately
			d.mu.Lock()
			remaining := len(d.batch)
			d.mu.Unlock()
			if remaining > batchMapMax/2 {
				d.flushBatch()
			}
		}
	}
}

func (d *Deduplicator) flushBatch() {
	d.mu.Lock()
	if len(d.batch) == 0 || d.db == nil {
		d.mu.Unlock()
		return
	}
	batch := d.batch
	d.batch = make(map[string]bool)
	d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO dedup_keys (key_hash, seen_at) VALUES (?, datetime('now'))")
	if err != nil {
		tx.Rollback()
		return
	}
	defer stmt.Close()

	i := 0
	for hash := range batch {
		stmt.Exec(hash)
		i++
		if i >= 50 {
			break
		}
	}
	tx.Commit()
}

func (d *Deduplicator) openDB(dataDir string) error {
	os.MkdirAll(dataDir, 0700)
	path := filepath.Join(dataDir, "dedup.db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(3000)")
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS dedup_keys (
		key_hash TEXT PRIMARY KEY,
		seen_at TEXT NOT NULL
	)`)
	if err != nil {
		db.Close()
		return err
	}
	d.db = db
	return nil
}

func (d *Deduplicator) loadMem() {
	if d.db == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.db.Query("SELECT key_hash FROM dedup_key WHERE seen_at > datetime('now', '-30 seconds')")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		rows.Scan(&hash)
		d.mem[hash] = time.Now()
	}
	log.Printf("[dedup] loaded %d keys from sqlite", len(d.mem))
}

func (d *Deduplicator) IsDuplicate(evt *Event) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := d.eventKey(evt)
	hash := sha256Hex(key)

	if _, exists := d.mem[hash]; exists {
		d.hitCount++
		return true
	}

	d.mem[hash] = time.Now()
	d.missCount++

	if d.db != nil {
		d.batch[hash] = true

		// Back-pressure: if batch is >75% full, wake the flusher
		if len(d.batch) >= batchMapMax {
			select {
			case d.batchCh <- struct{}{}:
			default:
			}
		} else if len(d.batch) >= batchFlushThr {
			select {
			case d.batchFull <- struct{}{}:
			default:
			}
		} else {
			select {
			case d.batchCh <- struct{}{}:
			default:
			}
		}
	}

	if len(d.mem) > d.maxMem {
		d.evictLocked()
	}

	return false
}

func (d *Deduplicator) eventKey(evt *Event) string {
	switch {
	case evt.Process != nil && evt.Process.PID > 0:
		return fmt.Sprintf("proc:%d:%s", evt.Process.PID, evt.Type)
	case evt.File != nil && evt.File.Path != "":
		return fmt.Sprintf("file:%s:%s", evt.File.Path, evt.Type)
	case evt.Network != nil:
		return fmt.Sprintf("net:%s:%d:%s:%s", evt.Network.RemoteIP, evt.Network.RemotePort, evt.Network.Protocol, evt.Type)
	default:
		return fmt.Sprintf("evt:%d", evt.Timestamp.UnixNano())
	}
}

func (d *Deduplicator) evictLocked() {
	cutoff := time.Now().Add(-d.ttl)
	for k, v := range d.mem {
		if v.Before(cutoff) {
			delete(d.mem, k)
		}
		if len(d.mem) <= d.maxMem*3/4 {
			break
		}
	}
}

func (d *Deduplicator) Stats() (int64, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hitCount, d.missCount
}

func (d *Deduplicator) Close() {
	close(d.done)
	if d.db != nil {
		d.db.Close()
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
