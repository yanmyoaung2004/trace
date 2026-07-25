//go:build !cgo

package cold

// NewDefaultReader returns a ColdReader implementation.
// When built with CGO, DuckDB is used for 5-10x faster queries.
// Without CGO, the pure-Go ParquetReader is used instead.
func NewDefaultReader() ColdReader {
	return NewParquetReader()
}

func init() {
	defaultReaderName = "parquet-go (pure Go)"
}
