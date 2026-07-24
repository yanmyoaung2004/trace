package metrics

import (
	"testing"
)

func TestMetrics_Snapshot(t *testing.T) {
	var m Metrics

	m.EventsEnqueued.Store(100)
	m.EventsWritten.Store(95)
	m.EventsFlushed.Store(80)
	m.EventsDropped.Store(5)
	m.EventsRead.Store(200)
	m.BatchesWritten.Store(10)
	m.BatchesFlushed.Store(8)
	m.QueueDepth.Store(2)
	m.WatermarkAge.Store(30)
	m.ParquetFilesCreated.Store(7)
	m.ParquetFilesDeleted.Store(3)
	m.ParquetBytesWritten.Store(1024000)
	m.HotTableCount.Store(4)
	m.ColdFileCount.Store(7)
	m.FlushErrors.Store(1)
	m.QueryErrors.Store(2)

	snap := m.Snapshot()

	tests := []struct {
		key      string
		expected int64
		unsigned bool
	}{
		{"events_enqueued", 100, false},
		{"events_written", 95, false},
		{"events_flushed", 80, false},
		{"events_dropped", 5, true},
		{"events_read", 200, false},
		{"batches_written", 10, false},
		{"batches_flushed", 8, false},
		{"queue_depth", 2, false},
		{"watermark_age_sec", 30, false},
		{"parquet_files_created", 7, false},
		{"parquet_files_deleted", 3, false},
		{"parquet_bytes_written", 1024000, false},
		{"hot_table_count", 4, false},
		{"cold_file_count", 7, false},
		{"flush_errors", 1, false},
		{"query_errors", 2, false},
	}

	for _, tt := range tests {
		got, ok := snap[tt.key]
		if !ok {
			t.Errorf("snapshot missing key %q", tt.key)
			continue
		}
		if tt.unsigned {
			v, ok := got.(uint64)
			if !ok {
				t.Errorf("snapshot[%q] type = %T, want uint64", tt.key, got)
				continue
			}
			if v != uint64(tt.expected) {
				t.Errorf("snapshot[%q] = %d, want %d", tt.key, v, tt.expected)
			}
		} else {
			v, ok := got.(int64)
			if !ok {
				t.Errorf("snapshot[%q] type = %T, want int64", tt.key, got)
				continue
			}
			if v != tt.expected {
				t.Errorf("snapshot[%q] = %d, want %d", tt.key, v, tt.expected)
			}
		}
	}
}

func TestMetrics_Global(t *testing.T) {
	Global.EventsEnqueued.Store(42)
	snap := Global.Snapshot()
	if snap["events_enqueued"] != int64(42) {
		t.Errorf("Global snapshot events_enqueued = %d, want 42", snap["events_enqueued"])
	}
	Global.EventsEnqueued.Store(0)
}

func TestMetrics_ZeroInit(t *testing.T) {
	var m Metrics
	snap := m.Snapshot()
	for k, v := range snap {
		switch val := v.(type) {
		case int64:
			if val != 0 {
				t.Errorf("zero-initialized snapshot[%q] = %d, want 0", k, val)
			}
		case uint64:
			if val != 0 {
				t.Errorf("zero-initialized snapshot[%q] = %d, want 0", k, val)
			}
		default:
			t.Errorf("snapshot[%q] type = %T, unexpected", k, v)
		}
	}
}
