package metrics

import (
	"fmt"
	"sync/atomic"
)

// promDesc returns the metric name, help, and type for a snapshot key.
var promMetrics = []struct {
	key  string
	name string
	help string
}{
	{"events_enqueued", "trace_tse_events_enqueued_total", "Total events enqueued"},
	{"events_dropped", "trace_tse_events_dropped_total", "Total events dropped"},
	{"events_written", "trace_tse_events_written_total", "Total events written to hot store"},
	{"events_flushed", "trace_tse_events_flushed_total", "Total events flushed to cold storage"},
	{"events_read", "trace_tse_events_read_total", "Total events read via queries"},
	{"batches_written", "trace_tse_batches_written_total", "Total batches written"},
	{"batches_flushed", "trace_tse_batches_flushed_total", "Total batches flushed"},
	{"queue_depth", "trace_tse_queue_depth", "Current queue depth"},
	{"watermark_age_sec", "trace_tse_watermark_age_seconds", "Seconds since last watermark advance"},
	{"parquet_files_created", "trace_tse_parquet_files_created_total", "Total parquet files created"},
	{"parquet_files_deleted", "trace_tse_parquet_files_deleted_total", "Total parquet files deleted"},
	{"parquet_bytes_written", "trace_tse_parquet_bytes_written_total", "Total bytes written to parquet files"},
	{"hot_table_count", "trace_tse_hot_table_count", "Current number of hot SQLite tables"},
	{"cold_file_count", "trace_tse_cold_file_count", "Current number of cold parquet files"},
	{"flush_errors", "trace_tse_flush_errors_total", "Total flush errors"},
	{"query_errors", "trace_tse_query_errors_total", "Total query errors"},
}

// PrometheusText returns all metrics in Prometheus exposition format.
func PrometheusText() string {
	snap := Global.Snapshot()
	var buf []byte

	for _, pm := range promMetrics {
		val, ok := snap[pm.key]
		if !ok {
			continue
		}
		buf = append(buf, "# HELP "...)
		buf = append(buf, pm.name...)
		buf = append(buf, ' ')
		buf = append(buf, pm.help...)
		buf = append(buf, '\n')
		buf = append(buf, "# TYPE "...)
		buf = append(buf, pm.name...)
		buf = append(buf, " gauge\n"...)
		buf = append(buf, pm.name...)
		buf = append(buf, ' ')
		switch v := val.(type) {
		case int64:
			buf = append(buf, fmt.Sprintf("%d", v)...)
		case uint64:
			buf = append(buf, fmt.Sprintf("%d", v)...)
		}
		buf = append(buf, '\n')
	}

	return string(buf)
}

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
