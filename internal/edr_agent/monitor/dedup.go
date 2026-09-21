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
	"sync/atomic"
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
		d.requeue(batch)
		return
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO dedup_keys (key_hash, seen_at) VALUES (?, datetime('now'))")
	if err != nil {
		tx.Rollback()
		d.requeue(batch)
		return
	}
	defer stmt.Close()

	ok := true
	for hash := range batch {
		if _, err := stmt.Exec(hash); err != nil {
			ok = false
			break
		}
	}
	if !ok {
		tx.Rollback()
		d.requeue(batch)
		return
	}
	if err := tx.Commit(); err != nil {
		d.requeue(batch)
	}
}

// requeue returns an unpersisted batch to memory so a failed flush retries
// instead of silently losing dedup state.
func (d *Deduplicator) requeue(batch map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for h := range batch {
		d.batch[h] = true
	}
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
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db == nil {
		return
	}
	rows, err := d.db.Query("SELECT key_hash FROM dedup_keys WHERE seen_at > datetime('now', '-30 seconds')")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return
		}
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
		atomic.AddInt64(&d.hitCount, 1)
		return true
	}

	d.mem[hash] = time.Now()
	atomic.AddInt64(&d.missCount, 1)

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
		return fmt.Sprintf("proc:%d:%s:%s:%s", evt.Process.PID, evt.Type, evt.Process.Name, evt.Process.CmdLine)
	case evt.File != nil && evt.File.Path != "":
		// Cookie/inode/mtime richer than path alone when available via Raw.
		cookie := fmt.Sprintf("%v", evt.Raw["cookie"])
		inode := fmt.Sprintf("%v", evt.Raw["inode"])
		mtime := fmt.Sprintf("%v", evt.Raw["mtime"])
		return fmt.Sprintf("file:%s:%s:%s:%s:%s:%d", evt.File.Path, evt.Type, cookie, inode, mtime, evt.File.Size)
	case evt.Network != nil:
		return fmt.Sprintf("net:%s:%d:%s:%s:%s:%d", evt.Network.RemoteIP, evt.Network.RemotePort, evt.Network.Protocol, evt.Type, evt.Network.Direction, evt.Network.PID)
	default:
		return fmt.Sprintf("evt:%s:%s:%d", evt.Type, evt.ID, evt.Timestamp.UnixNano())
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
	return atomic.LoadInt64(&d.hitCount), atomic.LoadInt64(&d.missCount)
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
