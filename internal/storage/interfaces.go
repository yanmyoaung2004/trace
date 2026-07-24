package storage

import (
	"context"
	"time"
)

// Writer is the universal ingestion primitive. Every storage component
// that accepts events implements this interface.
type Writer interface {
	// WriteBatch persists a batch of events atomically.
	WriteBatch(ctx context.Context, events []*Event) error

	// Close flushes pending data and releases resources.
	Close() error
}

// Reader is the universal query primitive. Every storage component
// that returns events implements this interface.
type Reader interface {
	// Query retrieves events matching the given query.
	Query(ctx context.Context, q Query) (*Result, error)
}

// Retention manages data lifecycle for a storage tier.
type Retention interface {
	// DeleteOlderThan removes data older than the cutoff time.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int, error)

	// DeleteByID removes all data with ID <= maxID.
	DeleteByID(ctx context.Context, maxID string) (int, error)
}

// Flusher moves data from the hot tier to the cold tier behind a watermark.
type Flusher interface {
	// Run is a blocking loop that continuously flushes data.
	Run(ctx context.Context) error

	// Watermark returns the current high-water mark.
	Watermark(ctx context.Context) (*Watermark, error)

	// FlushNow triggers an immediate flush cycle.
	FlushNow(ctx context.Context) error
}

// Compactor merges small Parquet files into larger ones.
type Compactor interface {
	// Run is a blocking loop that continuously compacts files.
	Run(ctx context.Context) error
}

// GC manages deletion of expired data.
type GC interface {
	// Run is a blocking loop that continuously collects garbage.
	Run(ctx context.Context) error
}

// ColdReader queries the cold storage tier (Parquet files).
type ColdReader interface {
	// QueryFiles retrieves events from the given Parquet files.
	QueryFiles(ctx context.Context, files []FileInfo, q Query) (*Result, error)

	// Name returns a human-readable name for this reader implementation.
	Name() string
}
