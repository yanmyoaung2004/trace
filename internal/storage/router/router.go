package router

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// Router transparently routes queries to the hot tier (SQLite) and cold tier
// (Parquet via ColdReader), merging results with deduplication by UUIDv7.
//
// The cutoff is the live watermark from the manifest, not a wall-clock value.
// A 10-minute overlap window prevents boundary race conditions.
type Router struct {
	hot      *sqlite.SQLiteHotStore
	cold     cold.ColdReader
	manifest *manifest.Manifest
}

// NewRouter creates a hot/cold query router.
func NewRouter(hot *sqlite.SQLiteHotStore, cr cold.ColdReader, m *manifest.Manifest) *Router {
	return &Router{
		hot:      hot,
		cold:     cr,
		manifest: m,
	}
}

// Query executes a query across both hot and cold tiers, merging results.
func (r *Router) Query(ctx context.Context, q storage.Query) (*storage.Result, error) {
	q = q.ApplyDefaults()
	wm, err := r.manifest.Watermark(ctx)
	if err != nil {
		return nil, fmt.Errorf("watermark: %w", err)
	}

	boundary := wm.LastTS
	overlap := int64(10 * time.Minute) // 10-min overlap in microseconds

	var (
		result   storage.Result
		mu       sync.Mutex
		hadError bool
	)

	// Determine if we need hot and/or cold queries
	needHot := q.SinceUs == 0 || q.UntilUs == 0 || q.UntilUs > boundary-overlap
	needCold := q.UntilUs == 0 || q.SinceUs < boundary+overlap

	var wg sync.WaitGroup
	errs := make(chan error, 2)

	// Hot query (SQLite): data newer than watermark - overlap
	if needHot {
		wg.Add(1)
		go func() {
			defer wg.Done()

			hotQ := q
			if hotQ.SinceUs == 0 || hotQ.SinceUs < boundary-overlap {
				hotQ.SinceUs = boundary - overlap
			}

			hotResult, err := r.hot.Query(ctx, hotQ)
			if err != nil {
				errs <- fmt.Errorf("hot query: %w", err)
				hadError = true
				return
			}

			mu.Lock()
			result.Events = append(result.Events, hotResult.Events...)
			result.Warnings = append(result.Warnings, hotResult.Warnings...)
			mu.Unlock()
		}()
	}

	// Cold query (Parquet via ColdReader): data older than watermark + overlap
	if needCold {
		wg.Add(1)
		go func() {
			defer wg.Done()

			files, err := r.manifest.FilesFor(ctx, q.TenantID, q.SinceUs, q.UntilUs, "committed")
			if err != nil {
				errs <- fmt.Errorf("manifest lookup: %w", err)
				hadError = true
				return
			}

			if len(files) == 0 {
				return
			}

			coldQ := q
			if coldQ.UntilUs == 0 || coldQ.UntilUs > boundary+overlap {
				coldQ.UntilUs = boundary + overlap
			}

			coldResult, err := r.cold.QueryFiles(ctx, files, coldQ)
			if err != nil {
				// Cold tier failure is non-fatal — return partial results with warning
				mu.Lock()
				result.Warnings = append(result.Warnings, fmt.Sprintf("cold tier: %v", err))
				mu.Unlock()
				return
			}

			mu.Lock()
			result.Events = append(result.Events, coldResult.Events...)
			result.Warnings = append(result.Warnings, coldResult.Warnings...)
			mu.Unlock()
		}()
	}

	wg.Wait()
	close(errs)

	// Collect errors (non-fatal in most cases)
	for e := range errs {
		result.Warnings = append(result.Warnings, e.Error())
	}

	// Merge, sort, dedup by ID
	if len(result.Events) > 1 {
		result.Events = storage.MergeSortDedupByID(result.Events)
	}

	// Cursor
	if len(result.Events) > 0 {
		result.Cursor = result.Events[len(result.Events)-1].ID
	}

	// Apply limit
	if q.Limit > 0 && len(result.Events) > q.Limit {
		result.Events = result.Events[:q.Limit]
	}

	result.Total = len(result.Events)

	if hadError {
		log.Printf("[router] query returned with errors: %v", result.Warnings)
	}

	return &result, nil
}
