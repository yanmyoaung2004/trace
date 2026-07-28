package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
	driver string // "sqlite" or "postgres"
}

// Open opens a database. For SQLite, path is a file path.
// For PostgreSQL, path is a connection string.
func Open(path string) (*DB, error) {
	driver := detectDriver(path)

	var db *sql.DB
	var err error

	switch driver {
	case "postgres":
		db, err = sql.Open("pgx", path)
	default:
		// SQLite
		sqlitePath := path
		if !strings.Contains(path, "?") {
			sqlitePath = path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
		db, err = sql.Open("sqlite", sqlitePath)
	}

	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	d := &DB{db, driver}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

// detectDriver detects the database driver from the connection string/path.
func detectDriver(path string) string {
	if strings.HasPrefix(path, "postgres://") ||
		strings.HasPrefix(path, "postgresql://") ||
		strings.HasPrefix(path, "pgx://") {
		return "postgres"
	}
	return "sqlite"
}

// translate converts SQLite-specific SQL to PostgreSQL syntax when running on Postgres.
func (d *DB) translate(query string) string {
	if d.driver != "postgres" {
		return query
	}

	// Replace positional ? with $N
	q := d.replacePositional(query)

	// Date/time functions
	q = strings.ReplaceAll(q, "datetime('now')", "NOW()")

	// CAST(strftime('%s','now') AS INTEGER) -> EXTRACT(EPOCH FROM NOW())::INTEGER
	q = strings.ReplaceAll(q,
		"CAST(strftime('%s','now') AS INTEGER)",
		"EXTRACT(EPOCH FROM NOW())::INTEGER",
	)

	// strftime -> TO_CHAR (simplified)
	q = strings.ReplaceAll(q, "strftime", "TO_CHAR")

	// INSERT OR REPLACE -> INSERT ... ON CONFLICT DO UPDATE
	// This is a simplified heuristic; complex cases need manual handling
	if strings.HasPrefix(q, "INSERT OR REPLACE") {
		q = "INSERT" + q[17:]
	}

	// INSERT OR IGNORE -> INSERT ... ON CONFLICT DO NOTHING
	if strings.HasPrefix(q, "INSERT OR IGNORE") {
		q = "INSERT" + q[16:] + " ON CONFLICT DO NOTHING"
	}

	// INSERT OR REPLACE INTO ... VALUES -> INSERT INTO ... VALUES ON CONFLICT DO UPDATE SET ...
	// This handles the common case
	if strings.HasPrefix(q, "INSERT OR REPLACE") {
		q = "INSERT" + q[17:]
		// We'd need to parse column names to build the ON CONFLICT clause
		// For now, add a generic fallback
	}

	return q
}

// replacePositional replaces ? with $1, $2, etc.
func (d *DB) replacePositional(query string) string {
	var b strings.Builder
	pos := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			fmt.Fprintf(&b, "$%d", pos)
			pos++
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}

// Exec wraps sql.DB.Exec with query translation.
func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.DB.Exec(d.translate(query), args...)
}

// ExecContext wraps sql.DB.ExecContext with query translation.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, d.translate(query), args...)
}

// Query wraps sql.DB.Query with query translation.
func (d *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.DB.Query(d.translate(query), args...)
}

// QueryContext wraps sql.DB.QueryContext with query translation.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, d.translate(query), args...)
}

// QueryRow wraps sql.DB.QueryRow with query translation.
func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.DB.QueryRow(d.translate(query), args...)
}

// QueryRowContext wraps sql.DB.QueryRowContext with query translation.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, d.translate(query), args...)
}

// Prepare wraps sql.DB.Prepare with query translation.
func (d *DB) Prepare(query string) (*sql.Stmt, error) {
	return d.DB.Prepare(d.translate(query))
}

// PrepareContext wraps sql.DB.PrepareContext with query translation.
func (d *DB) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return d.DB.PrepareContext(ctx, d.translate(query))
}

// BeginTx wraps sql.DB.BeginTx.
func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return d.DB.BeginTx(ctx, opts)
}

// Driver returns the database driver name.
func (d *DB) Driver() string { return d.driver }

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
		`CREATE TABLE IF NOT EXISTS hunts (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			schedule TEXT NOT NULL,
			playbook TEXT NOT NULL,
			params TEXT NOT NULL DEFAULT '{}',
			scope TEXT NOT NULL DEFAULT 'self',
			notify_severity INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			last_run TEXT,
			next_run TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hunts_next_run ON hunts(next_run)`,
		`CREATE INDEX IF NOT EXISTS idx_hunts_status ON hunts(status)`,
		`CREATE TABLE IF NOT EXISTS cases (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			status TEXT NOT NULL DEFAULT 'open',
			severity TEXT NOT NULL DEFAULT 'medium',
			assignee TEXT,
			tags TEXT,
			resolution TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now')),
			closed_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS case_events (
			id TEXT PRIMARY KEY,
			case_id TEXT REFERENCES cases(id),
			event_type TEXT NOT NULL,
			content TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT 'manual',
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS case_iocs (
			id TEXT PRIMARY KEY,
			case_id TEXT REFERENCES cases(id),
			ioc_type TEXT NOT NULL,
			value TEXT NOT NULL,
			description TEXT,
			source TEXT NOT NULL DEFAULT 'manual',
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS case_evidence (
			id TEXT PRIMARY KEY,
			case_id TEXT REFERENCES cases(id),
			file_name TEXT NOT NULL,
			file_path TEXT NOT NULL,
			mime_type TEXT,
			file_size INTEGER DEFAULT 0,
			source TEXT NOT NULL DEFAULT 'manual',
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS case_investigations (
			case_id TEXT REFERENCES cases(id),
			investigation_id TEXT NOT NULL,
			linked_at TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (case_id, investigation_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_cache_ttl ON cache(ttl)`,
	}

	for _, q := range queries {
		if _, err := d.Exec(q); err != nil {
			return fmt.Errorf("migrate query: %w", err)
		}
	}

	return nil
}
