package storage

import (
	"fmt"
	"sort"
	"time"
)

// Event is the core data unit in the Trace Storage Engine.
// It represents a normalized security event with columnar-decomposed fields.
type Event struct {
	ID          string            `json:"id"`           // UUIDv7
	TenantID    string            `json:"tenant_id"`    // multi-tenant isolation
	AgentID     string            `json:"agent_id"`     // endpoint identifier
	Timestamp   int64             `json:"ts_us"`        // epoch microseconds
	IngestedAt  int64             `json:"ingested_at"`  // epoch microseconds, for lateness auditing

	EventType   string            `json:"event_type"`
	Severity    int               `json:"severity"`

	// Columnar-decomposed JSON fields (5-10 hottest)
	ProcessName string            `json:"process_name,omitempty"`
	Cmdline     string            `json:"cmdline,omitempty"`
	ParentPID   int               `json:"parent_pid,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	DestIP      string            `json:"dest_ip,omitempty"`
	SrcIP       string            `json:"src_ip,omitempty"`
	UserName    string            `json:"user_name,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`

	// Residual JSON payload
	DataRaw     []byte            `json:"data_raw,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// DefaultMaxLimit is the maximum number of events a single query can return.
// This prevents OOM from unbounded queries across millions of events.
const DefaultMaxLimit = 100_000

// Query defines a storage-level query over events.
type Query struct {
	TenantID    string
	AgentIDs    []string
	EventTypes  []string
	MinSeverity int
	MinID       string       // UUIDv7 cursor for flusher (id > watermark)
	MaxID       string
	SinceUs     int64        // epoch microseconds
	UntilUs     int64
	Limit       int          // max rows to return (capped to DefaultMaxLimit)
	Cursor      string       // UUIDv7 continuation token for pagination
	OrderAsc    bool
}

// ApplyDefaults sets safe defaults for the query (limit, etc.).
func (q Query) ApplyDefaults() Query {
	if q.Limit <= 0 || q.Limit > DefaultMaxLimit {
		q.Limit = DefaultMaxLimit
	}
	return q
}

// Result holds query results with partial-failure warnings.
type Result struct {
	Events   []*Event
	Warnings []string
	Cursor   string // last UUIDv7 in this page, for continuation
	Total    int    // total matching (if computed)
}

// AddWarning records a non-fatal error that produced partial results.
func (r *Result) AddWarning(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// MergeSortDedupByID merges two event slices, deduplicating by UUIDv7 ID.
func MergeSortDedupByID(events []*Event) []*Event {
	if len(events) < 2 {
		return events
	}
	// Sort by UUIDv7 (which is time-ordered)
	sort.Slice(events, func(i, j int) bool {
		return events[i].ID < events[j].ID
	})
	// Dedup
	deduped := events[:1]
	for i := 1; i < len(events); i++ {
		if events[i].ID != events[i-1].ID {
			deduped = append(deduped, events[i])
		}
	}
	return deduped
}

// FileInfo describes a single committed Parquet file for query routing.
type FileInfo struct {
	Path     string `json:"path"`
	FileID   string `json:"file_id"`
	Status   string `json:"status"` // committed, superseded, etc.
	Level    int    `json:"level"`  // 0=hourly, 1=daily
	TenantID string `json:"tenant_id"`
	MinTS    int64  `json:"min_ts_us"`
	MaxTS    int64  `json:"max_ts_us"`
}

// ParquetFileRecord is the manifest record for a Parquet file.
type ParquetFileRecord struct {
	FileID           string `json:"file_id"`
	Path             string `json:"path"`
	TenantID         string `json:"tenant_id"`
	Level            int    `json:"level"`              // 0=hourly, 1=daily
	MinTimestampUs   int64  `json:"min_ts_us"`
	MaxTimestampUs   int64  `json:"max_ts_us"`
	MinEventID       string `json:"min_event_id"`
	MaxEventID       string `json:"max_event_id"`
	RowCount         int    `json:"row_count"`
	CompressedSize   int64  `json:"compressed_size"`
	UncompressedSize int64  `json:"uncompressed_size"`
	SHA256           string `json:"sha256"`
	Compression      string `json:"compression"`
	SchemaVersion    int    `json:"schema_version"`
	Status           string `json:"status"` // writing, committed, superseded, expired, corrupted, deleted
	CreatedAt        int64  `json:"created_at"`
	UpdatedAt        int64  `json:"updated_at"`
}

// Watermark is the singleton cursor tracking the last committed event.
type Watermark struct {
	LastID    string `json:"last_id"`     // UUIDv7 high-water mark
	LastTS    int64  `json:"last_ts_us"`  // epoch microseconds
	UpdatedAt int64  `json:"updated_at"`
}

// CompressionCodec defines the available Parquet compression algorithms.
type CompressionCodec string

const (
	CompressionZSTD   CompressionCodec = "zstd"
	CompressionSnappy CompressionCodec = "snappy"
	CompressionLZ4    CompressionCodec = "lz4"
	CompressionBrotli CompressionCodec = "brotli"
	CompressionNone   CompressionCodec = "none"
)

// FileResult is returned by the Parquet writer after a successful write.
type FileResult struct {
	Path             string
	RowCount         int
	CompressedSize   int64
	UncompressedSize int64
	SHA256           string
	MinTimestampUs   int64
	MaxTimestampUs   int64
	MinEventID       string
	MaxEventID       string
}

// HotTableRecord tracks an hourly SQLite table in the manifest.
type HotTableRecord struct {
	TableName string `json:"table_name"`
	HourStart int64  `json:"hour_start"` // epoch microseconds
	Status    string `json:"status"`     // active, flushed, dropped
}

// DefaultConfig returns the default TSE configuration.
func DefaultConfig() *Config {
	return &Config{
		StoragePath:   "./data/tse",
		Compression:   CompressionZSTD,
		QueueCapacity: 65536,
		BatchSize:     1000,
		BatchTimeout:  250 * time.Millisecond,
		HotWindow:     2 * time.Hour,
		FlushInterval: 30 * time.Second,
		ColdTTL:       365 * 24 * time.Hour,
		GCInterval:    24 * time.Hour,
		ScrubInterval: 168 * time.Hour,
	}
}

// Config holds all TSE configuration.
type Config struct {
	StoragePath   string           `json:"storage_path"`
	Compression   CompressionCodec `json:"compression"`
	QueueCapacity int              `json:"queue_capacity"`
	BatchSize     int              `json:"batch_size"`
	BatchTimeout  time.Duration    `json:"batch_timeout"`
	HotWindow     time.Duration    `json:"hot_window"`
	FlushInterval time.Duration    `json:"flush_interval"`
	ColdTTL       time.Duration    `json:"cold_ttl"`
	GCInterval    time.Duration    `json:"gc_interval"`
	ScrubInterval time.Duration    `json:"scrub_interval"`
}
