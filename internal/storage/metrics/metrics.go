package metrics

import (
	"sync/atomic"
)

// Metrics holds the key operational counters for the TSE.
// These can be exported via Prometheus or the /metrics endpoint.
type Metrics struct {
	EventsEnqueued      atomic.Int64
	EventsDropped       atomic.Uint64
	EventsWritten       atomic.Int64
	EventsFlushed       atomic.Int64
	EventsRead          atomic.Int64
	BatchesWritten      atomic.Int64
	BatchesFlushed      atomic.Int64

	QueueDepth          atomic.Int64
	WatermarkAge        atomic.Int64 // seconds since last watermark advance
	ParquetFilesCreated atomic.Int64
	ParquetFilesDeleted  atomic.Int64
	ParquetBytesWritten  atomic.Int64

	HotTableCount       atomic.Int64
	ColdFileCount       atomic.Int64

	FlushErrors         atomic.Int64
	QueryErrors         atomic.Int64
}

// Global is the shared metrics instance.
var Global Metrics

// Snapshot returns a consistent view of all counters.
func (m *Metrics) Snapshot() map[string]any {
	return map[string]any{
		"events_enqueued":       m.EventsEnqueued.Load(),
		"events_dropped":        m.EventsDropped.Load(),
		"events_written":        m.EventsWritten.Load(),
		"events_flushed":        m.EventsFlushed.Load(),
		"events_read":           m.EventsRead.Load(),
		"batches_written":       m.BatchesWritten.Load(),
		"batches_flushed":       m.BatchesFlushed.Load(),
		"queue_depth":           m.QueueDepth.Load(),
		"watermark_age_sec":     m.WatermarkAge.Load(),
		"parquet_files_created": m.ParquetFilesCreated.Load(),
		"parquet_files_deleted": m.ParquetFilesDeleted.Load(),
		"parquet_bytes_written": m.ParquetBytesWritten.Load(),
		"hot_table_count":       m.HotTableCount.Load(),
		"cold_file_count":       m.ColdFileCount.Load(),
		"flush_errors":          m.FlushErrors.Load(),
		"query_errors":          m.QueryErrors.Load(),
	}
}
