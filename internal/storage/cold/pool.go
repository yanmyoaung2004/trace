package cold

import (
	"context"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// DefaultMaxConcurrent is the default maximum number of concurrent
// Parquet file reads. Each read leaks goroutines from xitongsys/parquet-go,
// so this bounds the worst-case leak.
const DefaultMaxConcurrent = 4

// ReaderPool bounds concurrent Parquet reads to prevent OOM from
// goroutine leaks in xitongsys/parquet-go. This is a mitigation,
// not a fix — the library should be replaced.
type ReaderPool struct {
	sem   chan struct{}
	inner *ParquetReader
}

// NewReaderPool creates a pool that limits concurrent Parquet reads.
func NewReaderPool(maxConcurrent int) *ReaderPool {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	return &ReaderPool{
		sem:   make(chan struct{}, maxConcurrent),
		inner: NewParquetReader(),
	}
}

// QueryFiles reads events from Parquet files, bounded by the pool's
// concurrency limit.
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
	return "parquet-go (pooled)"
}
