//go:build !duckdb

package cold

import (
	"context"
	"fmt"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// DuckDBAnalytics is the DuckDB-based cold reader. It requires CGO and the
// duckdb build tag. The default build uses the pure-Go ParquetReader instead.
type DuckDBAnalytics struct{}

// NewDuckDBAnalytics creates a DuckDB analytics reader.
// In the default build, this returns an error explaining how to enable DuckDB.
func NewDuckDBAnalytics() *DuckDBAnalytics {
	return &DuckDBAnalytics{}
}

// Name returns the reader name.
func (d *DuckDBAnalytics) Name() string {
	return "DuckDB (requires -tags duckdb)"
}

// QueryFiles returns an error explaining that DuckDB requires the duckdb build tag.
func (d *DuckDBAnalytics) QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error) {
	return nil, fmt.Errorf("DuckDB analytics requires CGO: build with -tags duckdb")
}
