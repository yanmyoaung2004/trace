package manifest

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	_ "modernc.org/sqlite"
)

// DefaultDBPath is the default path for the manifest database.
const DefaultDBPath = "manifest.db"

// Manifest is the single source of truth for all committed Parquet files,
// the watermark cursor, and the hot table registry.
// It uses a separate SQLite database to avoid contention with the event store.
type Manifest struct {
	db *sql.DB
}

// NewManifest opens or creates the manifest database.
func NewManifest(path string) (*Manifest, error) {
	if path == "" {
		path = DefaultDBPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("manifest dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("manifest open: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("manifest pragma: %w", err)
		}
	}

	m := &Manifest{db: db}
	if err := m.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("manifest migrate: %w", err)
	}

	return m, nil
}

// migrate creates or updates the database schema.
func (m *Manifest) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS parquet_files (
			file_id TEXT PRIMARY KEY,
			path TEXT NOT NULL UNIQUE,
			tenant_id TEXT NOT NULL,
			level INTEGER NOT NULL DEFAULT 0,
			min_ts_us INTEGER NOT NULL,
			max_ts_us INTEGER NOT NULL,
			min_event_id TEXT NOT NULL,
			max_event_id TEXT NOT NULL,
			row_count INTEGER NOT NULL,
			compressed_size INTEGER NOT NULL,
			uncompressed_size INTEGER NOT NULL,
			sha256 TEXT NOT NULL,
			compression TEXT NOT NULL DEFAULT 'zstd',
			schema_version INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'writing',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pf_lookup ON parquet_files(tenant_id, status, min_ts_us, max_ts_us)`,
		`CREATE INDEX IF NOT EXISTS idx_pf_status ON parquet_files(status)`,

		`CREATE TABLE IF NOT EXISTS watermark (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			last_id TEXT NOT NULL,
			last_ts INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`INSERT OR IGNORE INTO watermark (id, last_id, last_ts, updated_at) VALUES (1, '', 0, 0)`,

		`CREATE TABLE IF NOT EXISTS hot_tables (
			table_name TEXT PRIMARY KEY,
			hour_start INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT 'active'
		)`,
	}

	for _, q := range queries {
		if _, err := m.db.Exec(q); err != nil {
			return fmt.Errorf("migrate query: %w", err)
		}
	}
	return nil
}

// AddFile records a committed Parquet file in the manifest.
func (m *Manifest) AddFile(ctx context.Context, file storage.ParquetFileRecord) error {
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO parquet_files (file_id, path, tenant_id, level,
			min_ts_us, max_ts_us, min_event_id, max_event_id,
			row_count, compressed_size, uncompressed_size,
			sha256, compression, schema_version, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'committed', ?, ?)
	`,
		file.FileID, file.Path, file.TenantID, file.Level,
		file.MinTimestampUs, file.MaxTimestampUs, file.MinEventID, file.MaxEventID,
		file.RowCount, file.CompressedSize, file.UncompressedSize,
		file.SHA256, file.Compression, file.SchemaVersion,
		file.CreatedAt, file.UpdatedAt,
	)
	return err
}

// AddFileTx records a committed Parquet file in the manifest using the given transaction.
func (m *Manifest) AddFileTx(ctx context.Context, tx *sql.Tx, file storage.ParquetFileRecord) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO parquet_files (file_id, path, tenant_id, level,
			min_ts_us, max_ts_us, min_event_id, max_event_id,
			row_count, compressed_size, uncompressed_size,
			sha256, compression, schema_version, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'committed', ?, ?)
	`,
		file.FileID, file.Path, file.TenantID, file.Level,
		file.MinTimestampUs, file.MaxTimestampUs, file.MinEventID, file.MaxEventID,
		file.RowCount, file.CompressedSize, file.UncompressedSize,
		file.SHA256, file.Compression, file.SchemaVersion,
		file.CreatedAt, file.UpdatedAt,
	)
	return err
}

// UpdateWatermarkTx advances the watermark to the given ID and timestamp using the given transaction.
func (m *Manifest) UpdateWatermarkTx(ctx context.Context, tx *sql.Tx, lastID string, lastTS int64) error {
	_, err := tx.ExecContext(ctx,
		"UPDATE watermark SET last_id = ?, last_ts = ?, updated_at = ? WHERE id = 1",
		lastID, lastTS, time.Now().UnixMicro(),
	)
	return err
}

// UpdateWatermark advances the watermark to the given ID and timestamp.
func (m *Manifest) UpdateWatermark(ctx context.Context, lastID string, lastTS int64) error {
	_, err := m.db.ExecContext(ctx,
		"UPDATE watermark SET last_id = ?, last_ts = ?, updated_at = ? WHERE id = 1",
		lastID, lastTS, time.Now().UnixMicro(),
	)
	return err
}

// Watermark returns the current high-water mark.
func (m *Manifest) Watermark(ctx context.Context) (*storage.Watermark, error) {
	var wm storage.Watermark
	err := m.db.QueryRowContext(ctx,
		"SELECT last_id, last_ts, updated_at FROM watermark WHERE id = 1",
	).Scan(&wm.LastID, &wm.LastTS, &wm.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("watermark: %w", err)
	}
	return &wm, nil
}

// FilesFor returns committed Parquet files matching the given filters.
func (m *Manifest) FilesFor(ctx context.Context, tenantID string, sinceUs, untilUs int64, status string) ([]storage.FileInfo, error) {
	query := "SELECT path, file_id, status, level, tenant_id, min_ts_us, max_ts_us FROM parquet_files WHERE 1=1"
	var args []any

	if tenantID != "" {
		query += " AND tenant_id = ?"
		args = append(args, tenantID)
	}
	if sinceUs > 0 {
		query += " AND max_ts_us >= ?"
		args = append(args, sinceUs)
	}
	if untilUs > 0 {
		query += " AND min_ts_us <= ?"
		args = append(args, untilUs)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	} else {
		query += " AND status = 'committed'"
	}
	query += " ORDER BY min_ts_us"

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("files for: %w", err)
	}
	defer rows.Close()

	var files []storage.FileInfo
	for rows.Next() {
		var f storage.FileInfo
		if err := rows.Scan(&f.Path, &f.FileID, &f.Status, &f.Level, &f.TenantID, &f.MinTS, &f.MaxTS); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// RegisterHotTable records an active hourly hot table.
func (m *Manifest) RegisterHotTable(ctx context.Context, tableName string, hourStart int64) error {
	_, err := m.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO hot_tables (table_name, hour_start, status) VALUES (?, ?, 'active')",
		tableName, hourStart,
	)
	return err
}

// MarkHotTableFlushed marks an hourly table as flushed (ready for DROP).
func (m *Manifest) MarkHotTableFlushed(ctx context.Context, tableName string) error {
	_, err := m.db.ExecContext(ctx,
		"UPDATE hot_tables SET status = 'flushed' WHERE table_name = ?", tableName,
	)
	return err
}

// DropHotTable removes a hot table from the registry after it's dropped.
func (m *Manifest) DropHotTable(ctx context.Context, tableName string) error {
	_, err := m.db.ExecContext(ctx,
		"UPDATE hot_tables SET status = 'dropped' WHERE table_name = ?", tableName,
	)
	return err
}

// UpdateFileStatus changes the status of a Parquet file.
func (m *Manifest) UpdateFileStatus(ctx context.Context, fileID, status string) error {
	_, err := m.db.ExecContext(ctx,
		"UPDATE parquet_files SET status = ?, updated_at = ? WHERE file_id = ?",
		status, time.Now().UnixMicro(), fileID,
	)
	return err
}

// Transaction executes a function within a manifest transaction.
// All manifest mutations should go through this to ensure atomicity.
func (m *Manifest) Transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("manifest tx begin: %w", err)
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}

// Close releases the manifest database connection.
func (m *Manifest) Close() error {
	return m.db.Close()
}

// OrphanGC deletes files on disk that are not in the manifest or have
// status='writing'. This should be called at startup to clean up after
// crashes during Parquet file writes.
func OrphanGC(ctx context.Context, dataDir string, m *Manifest) error {
	// List all Parquet files on disk
	var onDisk []string
	filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && filepath.Ext(path) == ".parquet" {
			onDisk = append(onDisk, path)
		}
		return nil
	})

	// Check each file against the manifest
	for _, path := range onDisk {
		var count int
		m.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM parquet_files WHERE path = ? AND status IN ('committed', 'superseded', 'expired')",
			path,
		).Scan(&count)

		if count == 0 {
			// File not in manifest (or had writing status from a crash)
			log.Printf("[manifest] orphan GC: removing %s", path)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Printf("[manifest] orphan GC remove error: %v", err)
			}
		}
	}

	return nil
}
