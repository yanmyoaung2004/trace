package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
)

// Status returns a human-readable summary of the TSE state.
func Status(ctx context.Context, m *manifest.Manifest, f *flusher.Flusher) (string, error) {
	wm, err := m.Watermark(ctx)
	if err != nil {
		return "", fmt.Errorf("watermark: %w", err)
	}

	meta := metrics.Global.Snapshot()

	watermarkAge := time.Duration(meta["watermark_age_sec"].(int64)) * time.Second

	status := fmt.Sprintf(`TSE Status:
  Watermark: %s (age: %v)
  Hot tables: %d
  Cold files: %d
  Events enqueued: %d
  Events written: %d
  Events flushed: %d
  Parquet files created: %d
  Parquet bytes written: %d
  Flush errors: %d
  Query errors: %d
`,
		wm.LastID, watermarkAge,
		meta["hot_table_count"], meta["cold_file_count"],
		meta["events_enqueued"], meta["events_written"],
		meta["events_flushed"], meta["parquet_files_created"],
		meta["parquet_bytes_written"], meta["flush_errors"],
		meta["query_errors"],
	)

	return status, nil
}

// FlushNow triggers an immediate flush cycle.
func FlushNow(ctx context.Context, f *flusher.Flusher) error {
	return f.FlushNow(ctx)
}

// Inspect lists recent Parquet files from the manifest.
func Inspect(ctx context.Context, m *manifest.Manifest, limit int) (string, error) {
	files, err := m.FilesFor(ctx, "", 0, 0, "committed")
	if err != nil {
		return "", err
	}

	if len(files) > limit {
		files = files[len(files)-limit:]
	}

	out := ""
	for _, f := range files {
		out += fmt.Sprintf("  %s  level=%d  events=%d..%d  %s\n",
			f.TenantID, f.Level, f.MinTS, f.MaxTS, f.Path)
	}
	if out == "" {
		out = "  No files in manifest\n"
	}
	return out, nil
}
