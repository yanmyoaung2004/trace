package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	_ "modernc.org/sqlite"
)

// DefaultDBPath is the default path for the hot store SQLite database.
const DefaultDBPath = "tse.db"

// SQLiteHotStore manages hourly hot tables for recent event data.
// It implements storage.Writer and storage.Reader for the hot tier.
type SQLiteHotStore struct {
	db        *sql.DB          // single connection (WAL mode handles concurrent reads)
	path      string
	tableFmt  string           // fmt string for hourly table names
	mu        sync.Mutex
	liveTables []string
}

// NewSQLiteHotStore opens or creates the hot store database.
// The writer connection is intended to be owned by a single goroutine.
// readerPoolSize controls the number of read-only connections.
func NewSQLiteHotStore(path string) (*SQLiteHotStore, error) {
	if path == "" {
		path = DefaultDBPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("hot store dir: %w", err)
	}

	// Writer connection — single connection, owned by WriterGoroutine
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("hot store open: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=-65536", // 64MB cache
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("hot store pragma: %w", err)
		}
	}

	s := &SQLiteHotStore{
		db:       db,
		path:     path,
		tableFmt: "edr_events_%s", // edr_events_2006010215
	}

	// Load existing live tables
	if err := s.refreshLiveTables(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("hot store live tables: %w", err)
	}

	return s, nil
}

// WriteBatch inserts a batch of events into an hourly table.
// It implements storage.Writer.
func (s *SQLiteHotStore) WriteBatch(ctx context.Context, events []*storage.Event) error {
	if len(events) == 0 {
		return nil
	}

	// Check disk space before accepting new events
	if storage.StoragePathFunc != nil {
		if du, err := storage.CheckDisk(storage.StoragePathFunc()); err == nil {
			if storage.IsDiskFull(du) {
				return storage.ErrDiskFull
			}
		}
	}

	// Determine which hourly table this batch belongs to
	tableName := hourlyTableName(events[0].Timestamp, s.tableFmt)

	// Ensure the table exists
	if err := s.ensureTable(ctx, tableName); err != nil {
		return fmt.Errorf("ensure table: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (id, tenant_id, agent_id, ts_us, ingested_at, event_type, severity,
			process_name, cmdline, parent_pid, sha256, dest_ip, src_ip, user_name, hostname, data_raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`, tableName))
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.ID, e.TenantID, e.AgentID, e.Timestamp, e.IngestedAt,
			e.EventType, e.Severity,
			nullableString(e.ProcessName), nullableString(e.Cmdline),
			nullableInt(e.ParentPID), nullableString(e.SHA256),
			nullableString(e.DestIP), nullableString(e.SrcIP),
			nullableString(e.UserName), nullableString(e.Hostname),
			e.DataRaw,
		); err != nil {
			return fmt.Errorf("insert: %w", err)
		}
	}

	return tx.Commit()
}

// Query retrieves events from the hot tier by querying all live hourly tables.
// It implements storage.Reader.
func (s *SQLiteHotStore) Query(ctx context.Context, q storage.Query) (*storage.Result, error) {
	q = q.ApplyDefaults()

	s.mu.Lock()
	tables := make([]string, len(s.liveTables))
	copy(tables, s.liveTables)
	s.mu.Unlock()

	if len(tables) == 0 {
		return &storage.Result{}, nil
	}

	// Build a UNION ALL query over all relevant tables
	query, args := buildHotQuery(tables, q)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return &storage.Result{Warnings: []string{fmt.Sprintf("hot query: %v", err)}}, nil
	}
	defer rows.Close()

	result := &storage.Result{}
	for rows.Next() {
		var e storage.Event
		var processName, cmdline, sha256, destIP, srcIP, userName, hostname sql.NullString
		var parentPid sql.NullInt64

		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.AgentID, &e.Timestamp, &e.IngestedAt,
			&e.EventType, &e.Severity,
			&processName, &cmdline, &parentPid, &sha256,
			&destIP, &srcIP, &userName, &hostname, &e.DataRaw,
		); err != nil {
			return &storage.Result{Warnings: append(result.Warnings, fmt.Sprintf("scan: %v", err))}, nil
		}
		e.ProcessName = processName.String
		e.Cmdline = cmdline.String
		e.SHA256 = sha256.String
		e.DestIP = destIP.String
		e.SrcIP = srcIP.String
		e.UserName = userName.String
		e.Hostname = hostname.String
		if parentPid.Valid {
			e.ParentPID = int(parentPid.Int64)
		}
		result.Events = append(result.Events, &e)
	}

	if q.Limit > 0 && len(result.Events) > q.Limit {
		result.Events = result.Events[:q.Limit]
	}
	if len(result.Events) > 0 {
		result.Cursor = result.Events[len(result.Events)-1].ID
	}
	result.Total = len(result.Events)

	return result, nil
}

// Close releases all database connections.
func (s *SQLiteHotStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ensureTable creates the hourly table if it doesn't exist.
func (s *SQLiteHotStore) ensureTable(ctx context.Context, tableName string) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id          TEXT PRIMARY KEY,
			tenant_id   TEXT NOT NULL,
			agent_id    TEXT NOT NULL,
			ts_us       INTEGER NOT NULL,
			ingested_at INTEGER NOT NULL,
			event_type  TEXT NOT NULL,
			severity    INTEGER NOT NULL,
			process_name TEXT,
			cmdline     TEXT,
			parent_pid  INTEGER,
			sha256      TEXT,
			dest_ip     TEXT,
			src_ip      TEXT,
			user_name   TEXT,
			hostname    TEXT,
			data_raw    BLOB
		)
	`, tableName))
	if err != nil {
		return err
	}

	// Create index only if it doesn't exist
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`
		CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(ts_us)
	`, tableName, tableName))
	if err != nil {
		return err
	}

	// Track as live table
	s.mu.Lock()
	found := false
	for _, t := range s.liveTables {
		if t == tableName {
			found = true
			break
		}
	}
	if !found {
		s.liveTables = append(s.liveTables, tableName)
	}
	s.mu.Unlock()

	return nil
}

// refreshLiveTables reads existing tables from the database.
func (s *SQLiteHotStore) refreshLiveTables(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name FROM sqlite_master
		WHERE type='table' AND name LIKE 'edr_events_%'
		ORDER BY name
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	s.mu.Lock()
	s.liveTables = s.liveTables[:0]
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		s.liveTables = append(s.liveTables, name)
	}
	s.mu.Unlock()
	return nil
}

// DropTable drops an hourly table. Called by retention after the table is
// fully flushed behind the watermark.
func (s *SQLiteHotStore) DropTable(ctx context.Context, tableName string) error {
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName)); err != nil {
		return fmt.Errorf("drop table %s: %w", tableName, err)
	}

	s.mu.Lock()
	filtered := s.liveTables[:0]
	for _, t := range s.liveTables {
		if t != tableName {
			filtered = append(filtered, t)
		}
	}
	s.liveTables = filtered
	s.mu.Unlock()

	log.Printf("[tse] dropped hot table: %s", tableName)
	return nil
}

// LiveTables returns a copy of the current live table names.
func (s *SQLiteHotStore) LiveTables(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tables := make([]string, len(s.liveTables))
	copy(tables, s.liveTables)
	return tables, nil
}

// hourlyTableName returns the hourly table name for a given timestamp.
func hourlyTableName(tsUs int64, format string) string {
	t := time.UnixMicro(tsUs)
	return fmt.Sprintf(format, t.Format("2006010215"))
}

// buildHotQuery constructs a UNION ALL query across hourly tables.
func buildHotQuery(tables []string, q storage.Query) (string, []any) {
	var args []any
	query := ""

	for i, table := range tables {
		if i > 0 {
			query += " UNION ALL "
		}
		query += fmt.Sprintf(`
			SELECT id, tenant_id, agent_id, ts_us, ingested_at,
				event_type, severity,
				process_name, cmdline, parent_pid, sha256,
				dest_ip, src_ip, user_name, hostname, data_raw
			FROM %s WHERE 1=1
		`, table)

		// Apply filters
		if q.MinID != "" {
			query += " AND id > ?"
			args = append(args, q.MinID)
		}
		if q.MaxID != "" {
			query += " AND id <= ?"
			args = append(args, q.MaxID)
		}
		if q.SinceUs > 0 {
			query += " AND ts_us >= ?"
			args = append(args, q.SinceUs)
		}
		if q.UntilUs > 0 {
			query += " AND ts_us < ?"
			args = append(args, q.UntilUs)
		}
		if q.MinSeverity > 0 {
			query += " AND severity >= ?"
			args = append(args, q.MinSeverity)
		}
		if len(q.AgentIDs) > 0 {
			query += fmt.Sprintf(" AND agent_id IN (%s)", placeholders(len(q.AgentIDs)))
			for _, a := range q.AgentIDs {
				args = append(args, a)
			}
		}
		if len(q.EventTypes) > 0 {
			query += fmt.Sprintf(" AND event_type IN (%s)", placeholders(len(q.EventTypes)))
			for _, et := range q.EventTypes {
				args = append(args, et)
			}
		}

		// Cursor-based pagination
		if q.Cursor != "" {
			query += " AND id > ?"
			args = append(args, q.Cursor)
		}
	}

	query += " ORDER BY id"

	if q.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", q.Limit)
	}

	return query, args
}

// placeholders generates a SQL placeholder string like "?,?,?,".
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, n*2-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}

// nullableString returns an empty string as nil for SQL NULL.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt(i int) interface{} {
	if i == 0 {
		return nil
	}
	return i
}
