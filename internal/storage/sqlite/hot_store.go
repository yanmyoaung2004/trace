package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	_ "modernc.org/sqlite"
)

// DefaultDBPath is the default path for the hot store SQLite database.
const DefaultDBPath = "tse.db"

// SQLiteHotStore manages hourly hot tables for recent event data.
// It implements storage.Writer and storage.Reader for the hot tier.
type SQLiteHotStore struct {
	db         *sql.DB
	path       string
	tableFmt   string
	mu         sync.Mutex
	liveTables []string
	ensured    map[string]bool
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
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=-262144",
		"PRAGMA temp_store=MEMORY",
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
		tableFmt: "edr_events_%s",
		ensured:  make(map[string]bool),
	}

	// Load existing live tables
	if err := s.refreshLiveTables(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("hot store live tables: %w", err)
	}

	return s, nil
}

// WriteBatch inserts a batch of events into hourly tables, splitting by hour.
// All hour groups commit in a single transaction; chunks exist only to respect
// the driver variable limit. Any error rolls back the whole batch (no partial
// commits) to preserve at-least-once + idempotent replay.
// It implements storage.Writer.
func (s *SQLiteHotStore) WriteBatch(ctx context.Context, events []*storage.Event) error {
	if len(events) == 0 {
		return nil
	}

	// W4: enforce the 95% disk-full gate at commit depth (direct writers that
	// bypass the queue) and emit the 85% warn at most once per minute.
	// The queue WriteBatch is the primary ingest gate; this is the backstop.
	if storage.StoragePathFunc != nil {
		if du, err := storage.GetDiskUsage(storage.StoragePathFunc()); err == nil {
			if storage.IsDiskFull(du) {
				metrics.Global.DiskFullRejected.Add(1)
				return storage.ErrDiskFull
			}
			storage.LogDiskWarn(du)
		}
	}

	// Split by hour (fix events[0]-only mis-partition).
	byHour := make(map[string][]*storage.Event)
	for _, e := range events {
		t := hourlyTableName(e.Timestamp, s.tableFmt)
		byHour[t] = append(byHour[t], e)
	}
	// Deterministic order for stable tests.
	tables := make([]string, 0, len(byHour))
	for t := range byHour {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		if err := s.ensureTable(ctx, t); err != nil {
			return fmt.Errorf("ensure table: %w", err)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// SQLite driver variable limit: chunk only to respect it.
	const maxVars = 999
	const varsPerEvent = 17
	maxEventBatch := maxVars / varsPerEvent
	if maxEventBatch < 1 {
		maxEventBatch = 1
	}
	for _, t := range tables {
		group := byHour[t]
		for i := 0; i < len(group); i += maxEventBatch {
			end := i + maxEventBatch
			if end > len(group) {
				end = len(group)
			}
			if err := s.insertChunkTx(ctx, tx, t, group[i:end]); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// insertChunkTx executes one multi-row INSERT inside the caller's transaction.
func (s *SQLiteHotStore) insertChunkTx(ctx context.Context, tx *sql.Tx, tableName string, events []*storage.Event) error {
	numCols := 17
	rowPlaceholders := "(" + strings.Repeat("?,", numCols-1) + "?)"
	allPlaceholders := strings.Repeat(rowPlaceholders+",", len(events)-1) + rowPlaceholders
	args := make([]any, 0, len(events)*numCols)
	for _, e := range events {
		args = append(args,
			e.ID, e.TenantID, e.AgentID, e.Timestamp, e.IngestedAt,
			e.EventType, e.Severity,
			nullableString(e.ProcessName), nullableString(e.Cmdline),
			nullableInt(e.ParentPID), nullableString(e.SHA256),
			nullableString(e.DestIP), nullableString(e.SrcIP),
			nullableString(e.UserName), nullableString(e.Hostname),
			e.DataRaw, nullableString(annotationsJSON(e)),
		)
	}

	query := fmt.Sprintf(
		`INSERT INTO %s (id, tenant_id, agent_id, ts_us, ingested_at, event_type, severity,
		 process_name, cmdline, parent_pid, sha256, dest_ip, src_ip, user_name, hostname, data_raw, annotations)
		 VALUES %s ON CONFLICT(id) DO NOTHING`,
		tableName, allPlaceholders,
	)

	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("multi-row insert: %w", err)
	}
	return nil
}

// Query retrieves events from the hot tier, pruning hourly tables by hour
// suffix (D2) and pushing tenant + per-table LIMIT down (P-H1).
// It implements storage.Reader.
func (s *SQLiteHotStore) Query(ctx context.Context, q storage.Query) (*storage.Result, error) {
	q = q.ApplyDefaults()

	s.mu.Lock()
	tables := make([]string, len(s.liveTables))
	copy(tables, s.liveTables)
	s.mu.Unlock()

	tables = pruneHotTables(tables, s.tableFmt, q.SinceUs, q.UntilUs)
	if len(tables) == 0 {
		return &storage.Result{}, nil
	}

	// Build a UNION ALL query over pruned tables
	query, args := buildHotQuery(tables, q)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return &storage.Result{Warnings: []string{fmt.Sprintf("hot query: %v", err)}}, nil
	}
	defer rows.Close()

	result := &storage.Result{}
	for rows.Next() {
		var e storage.Event
		var processName, cmdline, sha256, destIP, srcIP, userName, hostname, annotations sql.NullString
		var parentPid sql.NullInt64

		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.AgentID, &e.Timestamp, &e.IngestedAt,
			&e.EventType, &e.Severity,
			&processName, &cmdline, &parentPid, &sha256,
			&destIP, &srcIP, &userName, &hostname, &e.DataRaw, &annotations,
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
		if annotations.Valid && annotations.String != "" {
			var m map[string]string
			if err := json.Unmarshal([]byte(annotations.String), &m); err == nil {
				e.Annotations = m
			}
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

// DB exposes the writer connection for the WAL checkpointer (R2).
// Callers must not close it; Close on the store owns the lifecycle.
func (s *SQLiteHotStore) DB() *sql.DB { return s.db }

// WALSizeBytes reports the current hot.db-wal size, -1 when unknown (R2 metric).
func (s *SQLiteHotStore) WALSizeBytes() int64 {
	fi, err := os.Stat(s.path + "-wal")
	if err != nil {
		return -1
	}
	return fi.Size()
}

// Close releases all database connections.
func (s *SQLiteHotStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// hourlyTableName returns the hourly table name for a given timestamp.
func hourlyTableName(tsUs int64, format string) string {
	t := time.UnixMicro(tsUs)
	return fmt.Sprintf(format, t.Format("2006010215"))
}

// ensureTable creates the hourly table if it doesn't exist.
func (s *SQLiteHotStore) ensureTable(ctx context.Context, tableName string) error {
	s.mu.Lock()
	if s.ensured[tableName] {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

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
			data_raw    BLOB,
			annotations TEXT
		)
	`, tableName))
	if err != nil {
		return err
	}
	// Migration for pre-annotation tables: add column if missing.
	// Uses a savepoint-safe ALTER; duplicate-column error is ignored since
	// concurrent writers may race ensureTable on the same new table.
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN annotations TEXT`, tableName)); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}

	// Mark as ensured after successful DDL
	s.mu.Lock()
	s.ensured[tableName] = true
	s.mu.Unlock()

	// Composite indexes for tenant/time + type/time predicate pushdown (D1).
	// Added after write-bench consideration: reads are per-hour tables so the
	// extra index cost is one small B-tree per hour, not a global one.
	for _, idx := range []struct{ name, cols string }{
		{"ts", "(ts_us)"},
		{"tenant_ts", "(tenant_id, ts_us)"},
		{"type_ts", "(event_type, ts_us)"},
	} {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf(
			`CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s%s`, tableName, idx.name, tableName, idx.cols)); err != nil {
			return err
		}
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

// pruneHotTables drops hourly tables whose hour cannot overlap [sinceUs, untilUs).
// Tables carry an hour suffix yyyyMMddHH; unbounded queries keep all tables.
func pruneHotTables(tables []string, tableFmt string, sinceUs, untilUs int64) []string {
	if sinceUs <= 0 && untilUs <= 0 {
		return tables
	}
	// Derive table stem by formatting a known suffix: everything before it.
	sample := fmt.Sprintf(tableFmt, "2006010215")
	stem := strings.TrimSuffix(sample, "2006010215")
	kept := make([]string, 0, len(tables))
	for _, t := range tables {
		suffix := strings.TrimPrefix(t, stem)
		if len(suffix) != 10 {
			kept = append(kept, t) // unknown shape: keep rather than drop
			continue
		}
		hourStart, err := time.Parse("2006010215", suffix)
		if err != nil {
			kept = append(kept, t)
			continue
		}
		startUs := hourStart.UnixMicro()
		endUs := hourStart.Add(time.Hour).UnixMicro()
		if sinceUs > 0 && endUs <= sinceUs {
			continue
		}
		if untilUs > 0 && startUs >= untilUs {
			continue
		}
		kept = append(kept, t)
	}
	return kept
}

// buildHotQuery constructs a UNION ALL query across hourly tables.
// Each branch carries the tenant predicate (D3) and a per-table LIMIT so the
// cross-table ORDER BY+LIMIT does not sort unbounded rows (P-H1). The global
// LIMIT still applies after the merge.
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
				dest_ip, src_ip, user_name, hostname, data_raw, annotations
			FROM %s WHERE 1=1
		`, table)

		// Apply filters
		if q.TenantID != "" {
			query += " AND tenant_id = ?"
			args = append(args, q.TenantID)
		}
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

// annotationsJSON serializes event annotations for the hot annotations column (D4).
func annotationsJSON(e *storage.Event) string {
	if len(e.Annotations) == 0 {
		return ""
	}
	b, err := json.Marshal(e.Annotations)
	if err != nil {
		return ""
	}
	return string(b)
}

// placeholders generates a SQL placeholder string like "?,?,?".
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
