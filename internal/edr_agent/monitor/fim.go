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
	DataDir             string        `json:"-"`
}

type FIMMonitor struct {
	eventCh   chan<- *Event
	config    *FIMConfig
	db        *sql.DB
	done      chan struct{}
	mu        sync.Mutex
}

func NewFIMMonitor(eventCh chan<- *Event, cfg *FIMConfig) *FIMMonitor {
	return &FIMMonitor{
		eventCh: eventCh,
		config:  cfg,
		done:    make(chan struct{}),
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
	go f.pollingLoop(ctx)
	return nil
}

func (f *FIMMonitor) Stop() {
	close(f.done)
	if f.db != nil {
		f.db.Close()
	}
}

func (f *FIMMonitor) pollingLoop(ctx context.Context) {
	// Run first scan immediately
	f.scan()

	tick := time.NewTicker(f.config.ScanInterval)
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
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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

			// Only hash if file is small enough (first 1MB for hash)
			entry.HashSHA256 = f.hashFile(path, info.Size())

			current[path] = entry

			prev, exists := baseline[path]
			if !exists {
				// New file — add to baseline, emit create
				entry.FirstSeen = entry.LastSeen
				f.emitFIMEvent(path, entry, "fim_added")
			} else if prev.HashSHA256 != entry.HashSHA256 {
				// Hash changed — integrity violation
				f.emitFIMEvent(path, entry, "fim_modified")
			} else if prev.Mode != entry.Mode {
				// Permission change
				f.emitFIMEvent(path, entry, "fim_perm_change")
			}

			return nil
		})
		if err != nil {
			log.Printf("[fim] walk error %s: %v", root, err)
		}
	}

	// Detect deleted files
	for path, entry := range baseline {
		if _, exists := current[path]; !exists {
			f.emitFIMEvent(path, entry, "fim_deleted")
		}
	}

	// Persist updated baseline
	if err := f.saveBaseline(current); err != nil {
		log.Printf("[fim] save baseline: %v", err)
	}
}

func (f *FIMMonitor) loadBaseline() (map[string]FIMEntry, error) {
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
	tx, err := f.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete baseline entries not in current scan
	seen := make(map[string]bool, len(entries))
	for path := range entries {
		seen[path] = true
	}

	// Upsert all current entries
	upsert, err := tx.Prepare(`
		INSERT INTO fim_baseline (path, hash_sha256, size, mode, owner, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?,
			CASE WHEN EXISTS (SELECT 1 FROM fim_baseline WHERE path = ?) THEN (SELECT first_seen FROM fim_baseline WHERE path = ?) ELSE datetime('now') END,
			datetime('now'))
		ON CONFLICT(path) DO UPDATE SET
			hash_sha256 = excluded.hash_sha256,
			size = excluded.size,
			mode = excluded.mode,
			last_seen = datetime('now')
	`)
	if err != nil {
		return err
	}
	defer upsert.Close()

	for path, e := range entries {
		if _, err := upsert.Exec(e.Path, e.HashSHA256, e.Size, e.Mode, e.Owner, path, path); err != nil {
			return fmt.Errorf("upsert %s: %w", path, err)
		}
	}

	return tx.Commit()
}

func (f *FIMMonitor) hashFile(path string, size int64) string {
	hash := sha256.New()

	// For large files, hash only first 1MB
	readSize := size
	if readSize > 1*1024*1024 {
		readSize = 1 * 1024 * 1024
	}

	fh, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer fh.Close()

	if _, err := io.CopyN(hash, fh, readSize); err != nil && err != io.EOF {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (f *FIMMonitor) isExcluded(path string) bool {
	lower := strings.ToLower(path)
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
