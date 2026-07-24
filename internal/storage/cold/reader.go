package cold

import (
	"context"
	"fmt"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// ColdReader is the interface for querying the cold storage tier (Parquet files).
// The default implementation is the pure-Go ParquetReader.
// A DuckDB implementation is available behind the "duckdb" build tag.
type ColdReader interface {
	// QueryFiles retrieves events from the given Parquet files.
	QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error)

	// Name returns a human-readable name for this reader implementation.
	Name() string
}

// MergeResults merges multiple cold query results into a single sorted, deduplicated result.
// Results are merged in order and deduped by UUIDv7 ID.
func MergeResults(results []*storage.Result) *storage.Result {
	if len(results) == 0 {
		return &storage.Result{}
	}
	if len(results) == 1 {
		return results[0]
	}

	var total int
	for _, r := range results {
		total += len(r.Events)
	}

	all := make([]*storage.Event, 0, total)
	var warnings []string
	for _, r := range results {
		all = append(all, r.Events...)
		warnings = append(warnings, r.Warnings...)
	}

	deduped := storage.MergeSortDedupByID(all)

	result := &storage.Result{
		Events:   deduped,
		Warnings: warnings,
	}
	if len(deduped) > 0 {
		result.Cursor = deduped[len(deduped)-1].ID
	}
	result.Total = len(deduped)
	return result
}

// filePathList returns a comma-separated list of file paths for DuckDB read_parquet.
func filePathList(files []storage.FileInfo) []string {
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.Path
	}
	return paths
}

// Ensure queries are in range
func clampQuery(q storage.Query, minID, maxID string) storage.Query {
	if q.MinID != "" && q.MinID < minID {
		q.MinID = minID
	}
	if q.MaxID != "" && q.MaxID > maxID {
		q.MaxID = maxID
	}
	return q
}

// ErrColdUnavailable is returned when no cold reader is available.
var ErrColdUnavailable = fmt.Errorf("cold storage unavailable (build with -tags duckdb for faster queries)")
