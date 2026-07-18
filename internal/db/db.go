package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	d := &DB{db}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

func (d *DB) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS investigations (
			id TEXT PRIMARY KEY,
			status TEXT NOT NULL DEFAULT 'pending',
			intent TEXT NOT NULL,
			playbook TEXT,
			confidence REAL,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL REFERENCES investigations(id),
			agent TEXT NOT NULL,
			action TEXT NOT NULL,
			payload TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			result TEXT,
			error TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS results (
			id TEXT PRIMARY KEY,
			task_id TEXT NOT NULL REFERENCES tasks(id),
			agent TEXT NOT NULL,
			action TEXT NOT NULL,
			output TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS cache (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			ttl INTEGER NOT NULL DEFAULT 3600,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			investigation_id TEXT REFERENCES investigations(id),
			event_type TEXT NOT NULL,
			data TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			severity INTEGER NOT NULL DEFAULT 0,
			mapping TEXT,
			evidence TEXT,
			source TEXT NOT NULL,
			investigation_id TEXT REFERENCES investigations(id),
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_investigation ON tasks(investigation_id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_investigation ON events(investigation_id)`,
		`CREATE TABLE IF NOT EXISTS response_actions (
			id TEXT PRIMARY KEY,
			investigation_id TEXT REFERENCES investigations(id),
			action_name TEXT NOT NULL,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			command TEXT NOT NULL,
			output TEXT,
			rollback_command TEXT,
			rollback_status TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cache_ttl ON cache(ttl)`,
	}

	for _, q := range queries {
		if _, err := d.Exec(q); err != nil {
			return fmt.Errorf("migrate query: %w", err)
		}
	}

	return nil
}
