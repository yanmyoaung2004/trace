package parquet

// TraceEventParquet is the struct used for Parquet read/write operations.
// It mirrors storage.Event but with parquet-compatible types.
type TraceEventParquet struct {
	ID          string `parquet:"id,dictionary,optional"`
	TenantID    string `parquet:"tenant_id,dictionary,optional"`
	AgentID     string `parquet:"agent_id,dictionary,optional"`
	TimestampUs int64  `parquet:"ts_us"`
	IngestedAt  int64  `parquet:"ingested_at"`
	EventType   string `parquet:"event_type,dictionary,optional"`
	Severity    int32  `parquet:"severity"`
	ProcessName string `parquet:"process_name,dictionary,optional"`
	Cmdline     string `parquet:"cmdline,dictionary,optional"`
	ParentPID   int32  `parquet:"parent_pid,optional"`
	SHA256      string `parquet:"sha256,dictionary,optional"`
	DestIP      string `parquet:"dest_ip,dictionary,optional"`
	SrcIP       string `parquet:"src_ip,dictionary,optional"`
	UserName    string `parquet:"user_name,dictionary,optional"`
	Hostname    string `parquet:"hostname,dictionary,optional"`
	DataRaw     []byte `parquet:"data_raw,optional"`
}

// ParquetOptions configures Parquet file writing.
type ParquetOptions struct {
	Compression      string // zstd, snappy, lz4, brotli, uncompressed
	RowGroupSize     int    // target rows per row group
	CompressionLevel int    // compression level (0 = default)
}

// DefaultParquetOptions returns sensible defaults for Parquet writing.
func DefaultParquetOptions() ParquetOptions {
	return ParquetOptions{
		Compression:      "zstd",
		RowGroupSize:     1_000_000,
		CompressionLevel: 1,
	}
}

// ToParquetCompression converts a compression codec name to parquet library type.
// Deprecated: use parquet-go compression directly via WithCompression.
func ToParquetCompression(codec string) string {
	return codec
}
