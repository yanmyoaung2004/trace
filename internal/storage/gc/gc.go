package gc

import (
	"context"
	"log"
	"os"
	"time"

	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
)

// DefaultColdTTL is the default time-to-live for cold (parquet) data.
const DefaultColdTTL = 365 * 24 * time.Hour

// GC manages deletion of expired Parquet files with an audit trail.
// Files are marked as expired in the manifest first, then physically
// deleted after a grace period. The manifest row is kept permanently
// for compliance audit.
type GC struct {
	manifest *manifestpkg.Manifest
	dataDir  string
	interval time.Duration
	grace    time.Duration // grace period between expired and deleted
	coldTTL  time.Duration // TTL for cold data before marking expired
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
		grace:    7 * 24 * time.Hour,
		coldTTL:  DefaultColdTTL,
	}
}

// WithColdTTL sets the cold data TTL.
func (g *GC) WithColdTTL(ttl time.Duration) *GC {
	if ttl > 0 {
		g.coldTTL = ttl
	}
	return g
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
	now := time.Now()

	// 1. Clean up orphan parquet files from crashes (status=writing)
	if g.dataDir != "" {
		if err := manifestpkg.OrphanGC(ctx, g.dataDir, g.manifest); err != nil {
			log.Printf("[gc] orphan cleanup: %v", err)
		}
	}

	// 2. Enforce cold TTL: mark files older than TTL as expired
	ttlCutoff := now.Add(-g.coldTTL).UnixMicro()
	oldFiles, err := g.manifest.FilesFor(ctx, "", 0, ttlCutoff, "committed")
	if err == nil {
		for _, f := range oldFiles {
			if f.MaxTS < ttlCutoff {
				if err := g.manifest.UpdateFileStatus(ctx, f.FileID, "expired"); err != nil {
					log.Printf("[gc] mark expired %s: %v", f.FileID, err)
				} else {
					log.Printf("[gc] marked expired (TTL): %s (age=%v)", f.Path, now.Sub(time.UnixMicro(f.MaxTS)).Round(time.Hour))
				}
			}
		}
	}
	// Also mark superseded files past TTL
	supersededFiles, err := g.manifest.FilesFor(ctx, "", 0, ttlCutoff, "superseded")
	if err == nil {
		for _, f := range supersededFiles {
			if f.MaxTS < ttlCutoff {
				g.manifest.UpdateFileStatus(ctx, f.FileID, "expired")
			}
		}
	}

	// 3. Delete expired files past grace period
	gcCutoff := now.Add(-g.grace).UnixMicro()
	files, err := g.manifest.FilesFor(ctx, "", 0, gcCutoff, "expired")
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
