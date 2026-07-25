package gc

import (
	"context"
	"log"
	"os"
	"time"

	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
)

// GC manages deletion of expired Parquet files with an audit trail.
// Files are marked as expired in the manifest first, then physically
// deleted after a grace period. The manifest row is kept permanently
// for compliance audit.
type GC struct {
	manifest  *manifestpkg.Manifest
	dataDir   string
	interval  time.Duration
	grace     time.Duration // grace period between expired and deleted
}

// NewGC creates a garbage collector for Parquet files.
func NewGC(m *manifestpkg.Manifest, dataDir string, interval time.Duration) *GC {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &GC{
		manifest: m,
		dataDir:  dataDir,
		interval: interval,
		grace:    7 * 24 * time.Hour, // 7 day grace period
	}
}

// Run starts the GC loop. Blocks until context is cancelled.
func (g *GC) Run(ctx context.Context) error {
	log.Printf("[gc] started (interval=%v, grace=%v)", g.interval, g.grace)

	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			g.collectOnce(ctx)
		}
	}
}

// collectOnce executes a single GC cycle.
func (g *GC) collectOnce(ctx context.Context) {
	// 1. Clean up orphan parquet files from crashes (status=writing)
	if g.dataDir != "" {
		if err := manifestpkg.OrphanGC(ctx, g.dataDir, g.manifest); err != nil {
			log.Printf("[gc] orphan cleanup: %v", err)
		}
	}

	// 2. Delete expired files past grace period
	cutoff := time.Now().Add(-g.grace).UnixMicro()
	files, err := g.manifest.FilesFor(ctx, "", 0, cutoff, "expired")
	if err != nil {
		log.Printf("[gc] list expired: %v", err)
		return
	}

	for _, f := range files {
		if err := os.Remove(f.Path); err != nil && !os.IsNotExist(err) {
			log.Printf("[gc] remove expired %s: %v", f.Path, err)
			continue
		}
		if err := g.manifest.UpdateFileStatus(ctx, f.FileID, "deleted"); err != nil {
			log.Printf("[gc] mark deleted %s: %v", f.FileID, err)
		}
		log.Printf("[gc] deleted expired file: %s", f.Path)
	}
}
