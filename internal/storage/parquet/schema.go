package parquet

import (
	"github.com/xitongsys/parquet-go/parquet"
)

// TraceEventParquet is the struct used for Parquet read/write operations.
// It mirrors storage.Event but with parquet-compatible types.
type TraceEventParquet struct {
	ID          string `parquet:"name=id,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	TenantID    string `parquet:"name=tenant_id,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	AgentID     string `parquet:"name=agent_id,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	TimestampUs int64  `parquet:"name=ts_us,type=INT64"`
	IngestedAt  int64  `parquet:"name=ingested_at,type=INT64"`
	EventType   string `parquet:"name=event_type,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	Severity    int32  `parquet:"name=severity,type=INT32"`
	ProcessName string `parquet:"name=process_name,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	Cmdline     string `parquet:"name=cmdline,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	ParentPID   int32  `parquet:"name=parent_pid,type=INT32"`
	SHA256      string `parquet:"name=sha256,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	DestIP      string `parquet:"name=dest_ip,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	SrcIP       string `parquet:"name=src_ip,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	UserName    string `parquet:"name=user_name,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	Hostname    string `parquet:"name=hostname,type=BYTE_ARRAY,convertedtype=UTF8,encoding=PLAIN_DICTIONARY"`
	DataRaw     []byte `parquet:"name=data_raw,type=BYTE_ARRAY,valuetype=BYTE_ARRAY"`
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
func ToParquetCompression(codec string) parquet.CompressionCodec {
	switch codec {
	case "snappy":
		return parquet.CompressionCodec_SNAPPY
	case "lz4":
		return parquet.CompressionCodec_LZ4
	case "brotli":
		return parquet.CompressionCodec_BROTLI
	case "uncompressed", "none":
		return parquet.CompressionCodec_UNCOMPRESSED
	default:
		return parquet.CompressionCodec_ZSTD
	}
}

