package router

import (
	"context"
	"fmt"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

const (
	// DefaultPageSize is the default number of events per page.
	DefaultPageSize = 1000

	// MaxPageSize is the maximum number of events per page.
	MaxPageSize = 10000
)

// QueryWithCursor executes a cursor-based paginated query.
// The Cursor field in the query is the last UUIDv7 seen from the previous page.
// Returns the result with the next cursor for continuation.
func (r *Router) QueryWithCursor(ctx context.Context, q storage.Query) (*storage.Result, error) {
	if q.Limit <= 0 {
		q.Limit = DefaultPageSize
	}
	if q.Limit > MaxPageSize {
		q.Limit = MaxPageSize
	}

	result, err := r.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("cursor query: %w", err)
	}

	// The cursor is already set by Query() to the last event ID.
	return result, nil
}

// ParseCursor extracts the cursor value from a previous result for use in the next query.
func ParseCursor(result *storage.Result) string {
	if result == nil {
		return ""
	}
	return result.Cursor
}
