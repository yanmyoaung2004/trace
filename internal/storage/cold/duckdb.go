//go:build cgo

package cold

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// DuckDBAnalytics is the DuckDB-based cold reader.
// It provides 5-10x faster queries than the pure-Go ParquetReader
// by using DuckDB's columnar-vectorized execution engine.
//
// DuckDB never stores data. It reads Parquet files directly from
// the manifest using read_parquet(). No import, no duplication.
type DuckDBAnalytics struct {
	db *sql.DB
}

// NewDuckDBAnalytics creates a DuckDB analytics reader.
func NewDuckDBAnalytics() *DuckDBAnalytics {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return &DuckDBAnalytics{}
	}
	// Configure DuckDB for analytical queries
	db.Exec("SET threads TO 4")
	db.Exec("SET memory_limit = '2GB'")
	return &DuckDBAnalytics{db: db}
}

// Name returns the reader name.
func (d *DuckDBAnalytics) Name() string {
	return "DuckDB (CGO, vectorized)"
}

// QueryFiles executes a query over the given Parquet files using DuckDB.
// Only committed files from the manifest are queried — no filesystem glob,
// no orphan risk.
func (d *DuckDBAnalytics) QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error) {
	if d.db == nil {
		return nil, fmt.Errorf("DuckDB not initialized")
	}
	if len(files) == 0 {
		return &storage.Result{}, nil
	}

	// Build file list
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = fmt.Sprintf("'%s'", f.Path)
	}
	fileList := strings.Join(paths, ", ")

	// Build DuckDB query
	where := buildDuckDBWhere(q)
	query := fmt.Sprintf(`
		SELECT id, tenant_id, agent_id, ts_us, ingested_at,
			event_type, severity,
			process_name, cmdline, parent_pid, sha256,
			dest_ip, src_ip, user_name, hostname, data_raw
		FROM read_parquet([%s])
		%s
		ORDER BY id
	`, fileList, where)

	if q.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", q.Limit)
	}

	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("duckdb query: %w", err)
	}
	defer rows.Close()

	result := &storage.Result{}
	for rows.Next() {
		var (
			e               storage.Event
			processName, cmdline, sha256, destIP, srcIP, userName, hostname sql.NullString
			parentPid       sql.NullInt64
		)
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.AgentID, &e.Timestamp, &e.IngestedAt,
			&e.EventType, &e.Severity,
			&processName, &cmdline, &parentPid, &sha256,
			&destIP, &srcIP, &userName, &hostname, &e.DataRaw,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
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

	if len(result.Events) > 0 {
		result.Cursor = result.Events[len(result.Events)-1].ID
	}
	result.Total = len(result.Events)

	return result, nil
}

// buildDuckDBWhere builds a DuckDB WHERE clause from the query.
func buildDuckDBWhere(q storage.Query) string {
	var clauses []string

	if q.MinID != "" {
		clauses = append(clauses, fmt.Sprintf("id > '%s'", escape(q.MinID)))
	}
	if q.MaxID != "" {
		clauses = append(clauses, fmt.Sprintf("id <= '%s'", escape(q.MaxID)))
	}
	if q.SinceUs > 0 {
		clauses = append(clauses, fmt.Sprintf("ts_us >= %d", q.SinceUs))
	}
	if q.UntilUs > 0 {
		clauses = append(clauses, fmt.Sprintf("ts_us < %d", q.UntilUs))
	}
	if q.MinSeverity > 0 {
		clauses = append(clauses, fmt.Sprintf("severity >= %d", q.MinSeverity))
	}
	if len(q.AgentIDs) > 0 {
		quoted := make([]string, len(q.AgentIDs))
		for i, a := range q.AgentIDs {
			quoted[i] = fmt.Sprintf("'%s'", escape(a))
		}
		clauses = append(clauses, fmt.Sprintf("agent_id IN (%s)", strings.Join(quoted, ",")))
	}
	if len(q.EventTypes) > 0 {
		quoted := make([]string, len(q.EventTypes))
		for i, e := range q.EventTypes {
			quoted[i] = fmt.Sprintf("'%s'", escape(e))
		}
		clauses = append(clauses, fmt.Sprintf("event_type IN (%s)", strings.Join(quoted, ",")))
	}
	if q.Cursor != "" {
		clauses = append(clauses, fmt.Sprintf("id > '%s'", escape(q.Cursor)))
	}

	if len(clauses) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(clauses, " AND ")
}

// escape escapes single quotes in string literals.
func escape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// Close releases the DuckDB database connection.
func (d *DuckDBAnalytics) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
