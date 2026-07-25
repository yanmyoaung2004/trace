package cold

import (
	"context"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// DefaultMaxConcurrent is the default maximum number of concurrent reads.
const DefaultMaxConcurrent = 4

// ReaderPool bounds concurrent cold reads with a semaphore.
type ReaderPool struct {
	sem   chan struct{}
	inner ColdReader
}

// NewReaderPool creates a pool that limits concurrent reads.
func NewReaderPool(maxConcurrent int) *ReaderPool {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	return &ReaderPool{
		sem:   make(chan struct{}, maxConcurrent),
		inner: NewParquetReader(),
	}
}

// QueryFiles reads events from Parquet files, bounded by the pool.
func (p *ReaderPool) QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error) {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-p.sem }()

	return p.inner.QueryFiles(ctx, files, q)
}

// Name returns the reader name.
func (p *ReaderPool) Name() string {
	return p.inner.Name() + " (pooled)"
}

// SetReader replaces the underlying reader (e.g., switch to DuckDB at runtime).
func (p *ReaderPool) SetReader(r ColdReader) {
	p.inner = r
}
