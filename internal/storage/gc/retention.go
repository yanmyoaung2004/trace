package gc

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// Retention drops flushed hot tables behind the watermark + HotWindow (D8).
// The flusher never drops: only this job removes hourly tables, and only when
// the table's hour ended before both the watermark and the hot window. Every
// drop is counted via RetentionDroppedTables.
type Retention struct {
	manifest  *manifestpkg.Manifest
	hot       *sqlite.SQLiteHotStore
	hotWindow time.Duration
	interval  time.Duration
}

// NewRetention creates the hot-table retention job.
func NewRetention(m *manifestpkg.Manifest, hot *sqlite.SQLiteHotStore, hotWindow, interval time.Duration) *Retention {
	if hotWindow <= 0 {
		hotWindow = 2 * time.Hour
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Retention{manifest: m, hot: hot, hotWindow: hotWindow, interval: interval}
}

// Run starts the retention loop. Blocks until context is cancelled.
func (r *Retention) Run(ctx context.Context) error {
	log.Printf("[retention] started (window=%v, interval=%v)", r.hotWindow, r.interval)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.retainOnce(ctx)
		}
	}
}

// retainOnce drops tables whose hour ended before the watermark and aged out
// of the hot window.
func (r *Retention) retainOnce(ctx context.Context) {
	wm, err := r.manifest.Watermark(ctx)
	if err != nil {
		log.Printf("[retention] watermark: %v", err)
		return
	}
	tables, err := r.hot.LiveTables(ctx)
	if err != nil {
		log.Printf("[retention] live tables: %v", err)
		return
	}
	now := time.Now().UnixMicro()
	for _, t := range tables {
		hourStart, ok := parseHourSuffix(t)
		if !ok {
			continue
		}
		hourEnd := hourStart + int64(time.Hour/time.Microsecond)
		if hourEnd >= wm.LastTS {
			continue // at or ahead of watermark: still flushing
		}
		if hourEnd+r.hotWindow.Microseconds() >= now {
			continue // inside hot window: keep for queries
		}
		if err := r.hot.DropTable(ctx, t); err != nil {
			log.Printf("[retention] drop %s: %v", t, err)
			continue
		}
		_ = r.manifest.MarkHotTableFlushed(ctx, t)
		_ = r.manifest.DropHotTable(ctx, t)
		metrics.Global.RetentionDroppedTables.Add(1)
		log.Printf("[retention] dropped %s (watermark=%d)", t, wm.LastTS)
	}
}

// parseHourSuffix extracts the hour start (epoch microseconds) from an hourly
// table name suffix yyyyMMddHH.
func parseHourSuffix(table string) (int64, bool) {
	idx := strings.LastIndex(table, "_")
	if idx < 0 || idx+11 != len(table) {
		return 0, false
	}
	suffix := table[idx+1:]
	if len(suffix) != 10 {
		return 0, false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			_, _ = strconv.Itoa(0)
			return 0, false
		}
	}
	hour, err := time.Parse("2006010215", suffix)
	if err != nil {
		return 0, false
	}
	return hour.UnixMicro(), true
}
