package monitor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type FIMEntry struct {
	Path      string
	HashSHA256 string
	Size      int64
	Mode      string
	Owner     string
	FirstSeen string
	LastSeen  string
}

type FIMConfig struct {
	Enabled             bool          `json:"monitor_fim"`
	WatchPaths          []string      `json:"fim_watch_paths"`
	ExcludePatterns     []string      `json:"fim_exclude_patterns"`
	MaxSizeMB           int           `json:"fim_max_size_mb"`
	ScanInterval        time.Duration `json:"fim_scan_interval"`
	CooldownCount       int           `json:"fim_cooldown_count"`
	DataDir             string        `json:"-"`
}

type FIMMonitor struct {
	eventCh  chan<- *Event
	config   *FIMConfig
	db       *sql.DB
	done     chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	flapCount map[string]int
	flapMu   sync.Mutex
}

func NewFIMMonitor(eventCh chan<- *Event, cfg *FIMConfig) *FIMMonitor {
	return &FIMMonitor{
		eventCh:   eventCh,
		config:    cfg,
		done:      make(chan struct{}),
		flapCount: make(map[string]int),
	}
}

func (f *FIMMonitor) Start(ctx context.Context) error {
	dbPath := filepath.Join(f.config.DataDir, "fim.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return fmt.Errorf("fim db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("fim db open: %w", err)
	}
	f.db = db

	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		CREATE TABLE IF NOT EXISTS fim_baseline (
			path TEXT PRIMARY KEY,
			hash_sha256 TEXT NOT NULL,
			size INTEGER NOT NULL DEFAULT 0,
			mode TEXT NOT NULL DEFAULT '',
			owner TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL DEFAULT (datetime('now')),
			last_seen TEXT NOT NULL DEFAULT (datetime('now'))
		);
		CREATE INDEX IF NOT EXISTS idx_fim_hash ON fim_baseline(hash_sha256);
	`); err != nil {
		return fmt.Errorf("fim db migrate: %w", err)
	}

	log.Printf("[fim] started (paths=%d, interval=%v)", len(f.config.WatchPaths), f.config.ScanInterval)
	f.wg.Add(1)
	go f.pollingLoop(ctx)
	return nil
}

func (f *FIMMonitor) Stop() {
	close(f.done)
	f.wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.db != nil {
		f.db.Close()
		f.db = nil
	}
}

func (f *FIMMonitor) pollingLoop(ctx context.Context) {
	defer f.wg.Done()
	f.scan()

	interval := f.config.ScanInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-f.done:
			return
		case <-tick.C:
			f.scan()
		}
	}
}

func (f *FIMMonitor) scan() {
	f.mu.Lock()
	defer f.mu.Unlock()

	baseline, err := f.loadBaseline()
	if err != nil {
		log.Printf("[fim] load baseline: %v", err)
		return
	}

	current := make(map[string]FIMEntry)
	maxSize := int64(f.config.MaxSizeMB) * 1024 * 1024

	for _, root := range f.config.WatchPaths {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if f.isExcluded(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Size() > maxSize {
				return nil
			}
			if f.isExcluded(path) {
				return nil
			}

			entry := FIMEntry{
				Path:     path,
				Size:     info.Size(),
				Mode:     info.Mode().String(),
				LastSeen: time.Now().UTC().Format(time.RFC3339),
			}

			hash, err := f.hashFile(path)
			if err != nil {
				return nil
			}
			entry.HashSHA256 = hash
			current[path] = entry

			prev, exists := baseline[path]
			if !exists {
				entry.FirstSeen = entry.LastSeen
				if !f.isFlapping(path) {
					f.emitFIMEvent(path, entry, "fim_added")
				}
			} else if prev.HashSHA256 != entry.HashSHA256 {
				if !f.isFlapping(path) {
					f.emitFIMEvent(path, entry, "fim_modified")
				}
			} else if prev.Mode != entry.Mode {
				f.emitFIMEvent(path, entry, "fim_perm_change")
			}

			return nil
		})
	}

	for path, entry := range baseline {
		if _, exists := current[path]; !exists {
			f.emitFIMEvent(path, entry, "fim_deleted")
		}
	}

	if err := f.saveBaseline(current); err != nil {
		log.Printf("[fim] save baseline: %v", err)
	}
}

func (f *FIMMonitor) isFlapping(path string) bool {
	f.flapMu.Lock()
	defer f.flapMu.Unlock()
	f.flapCount[path]++
	if f.flapCount[path] > 3 {
		log.Printf("[fim] flapping suppressed: %s", path)
		// Reset after 10 scan cycles
		if f.flapCount[path] > 10 {
			delete(f.flapCount, path)
		}
		return true
	}
	return false
}

func (f *FIMMonitor) loadBaseline() (map[string]FIMEntry, error) {
	if f.db == nil {
		return make(map[string]FIMEntry), nil
	}
	rows, err := f.db.Query(`SELECT path, hash_sha256, size, mode, owner, first_seen, last_seen FROM fim_baseline`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	baseline := make(map[string]FIMEntry)
	for rows.Next() {
		var e FIMEntry
		if err := rows.Scan(&e.Path, &e.HashSHA256, &e.Size, &e.Mode, &e.Owner, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		baseline[e.Path] = e
	}
	return baseline, nil
}

func (f *FIMMonitor) saveBaseline(entries map[string]FIMEntry) error {
	if f.db == nil {
		return fmt.Errorf("db closed")
	}
	tx, err := f.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete entries for files that no longer exist
	if _, err := tx.Exec(`DELETE FROM fim_baseline`); err != nil {
		return fmt.Errorf("delete baseline: %w", err)
	}

	// Batch insert all current entries
	stmt, err := tx.Prepare(`INSERT INTO fim_baseline (path, hash_sha256, size, mode, owner, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		if _, err := stmt.Exec(e.Path, e.HashSHA256, e.Size, e.Mode, e.Owner); err != nil {
			return fmt.Errorf("insert %s: %w", e.Path, err)
		}
	}

	return tx.Commit()
}

func (f *FIMMonitor) hashFile(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer fh.Close()

	hash := sha256.New()
	if _, err := io.CopyN(hash, fh, 1*1024*1024); err != nil && err != io.EOF {
		return "", fmt.Errorf("read: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (f *FIMMonitor) isExcluded(path string) bool {
	lower := strings.ToLower(path)
	// Always exclude our own SQLite files
	if strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".db-wal") || strings.HasSuffix(lower, ".db-shm") {
		return true
	}
	for _, ex := range f.config.ExcludePatterns {
		if strings.Contains(lower, strings.ToLower(ex)) {
			return true
		}
	}
	return false
}

func (f *FIMMonitor) emitFIMEvent(path string, entry FIMEntry, changeType string) {
	sev := SeverityWarning
	if changeType == "fim_modified" || changeType == "fim_deleted" {
		sev = SeverityAlert
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Type:      EventAlert,
		Severity:  sev,
		File: &FileInfo{
			Path: path,
			Size: entry.Size,
			Mode: entry.Mode,
			Hash: entry.HashSHA256,
		},
		Annotations: map[string]string{
			"source":      "fim",
			"change_type": changeType,
			"hash_sha256": entry.HashSHA256,
			"path":        path,
		},
	}

	select {
	case f.eventCh <- evt:
	default:
	}
}
