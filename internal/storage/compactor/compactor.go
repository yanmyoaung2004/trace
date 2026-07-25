package compactor

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
)

// Compactor merges hourly Parquet files into daily files after 48 hours.
// It follows the same atomic-manifest-commit discipline as the flusher.
type Compactor struct {
	manifest *manifestpkg.Manifest
	reader   cold.ColdReader
	writer   *parquet.ParquetWriter
	interval time.Duration
	grace    time.Duration // grace period before deleting superseded files
}

// NewCompactor creates a compactor that runs at the given interval.
func NewCompactor(
	m *manifestpkg.Manifest,
	cr cold.ColdReader,
	pw *parquet.ParquetWriter,
	interval time.Duration,
) *Compactor {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &Compactor{
		manifest: m,
		reader:   cr,
		writer:   pw,
		interval: interval,
		grace:    1 * time.Hour,
	}
}

// Run starts the compaction loop. Blocks until context is cancelled.
func (c *Compactor) Run(ctx context.Context) error {
	log.Printf("[compactor] started (interval=%v)", c.interval)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.compactOnce(ctx)
		}
	}
}

// compactOnce executes a single compaction cycle.
func (c *Compactor) compactOnce(ctx context.Context) {
	cutoff := time.Now().Add(-48 * time.Hour).UnixMicro()

	// Find hourly files older than 48h that are still committed
	// Group by (tenant_id, date) for daily merging
	files, err := c.manifest.FilesFor(ctx, "", 0, cutoff, "committed")
	if err != nil {
		log.Printf("[compactor] list files: %v", err)
		return
	}

	// Group by (tenant_id, date)
	type groupKey struct {
		tenantID string
		date     string
	}
	groups := make(map[groupKey][]storage.FileInfo)
	for _, f := range files {
		if f.Level != 0 { // only hourly files
			continue
		}
		date := time.UnixMicro(f.MinTS).Format("2006-01-02")
		key := groupKey{tenantID: f.TenantID, date: date}
		groups[key] = append(groups[key], f)
	}

	for key, groupFiles := range groups {
		if len(groupFiles) < 2 {
			continue // single file — no merge needed
		}

		if err := c.compactGroup(ctx, key.tenantID, key.date, groupFiles); err != nil {
			log.Printf("[compactor] compact %s/%s: %v", key.tenantID, key.date, err)
		}
	}
}

// compactGroup merges a group of hourly files into a daily file.
func (c *Compactor) compactGroup(ctx context.Context, tenantID, date string, files []storage.FileInfo) error {
	log.Printf("[compactor] merging %d files for %s/%s", len(files), tenantID, date)

	// Sort files by timestamp
	sort.Slice(files, func(i, j int) bool {
		return files[i].MinTS < files[j].MinTS
	})

	// Read all events from hourly files
	var allEvents []*storage.Event
	for _, f := range files {
		result, err := c.reader.QueryFiles(ctx, []storage.FileInfo{f}, storage.Query{})
		if err != nil {
			return fmt.Errorf("read %s: %w", f.Path, err)
		}
		allEvents = append(allEvents, result.Events...)
	}

	if len(allEvents) == 0 {
		return nil
	}

	// Sort by (agent_id, timestamp)
	sort.Slice(allEvents, func(i, j int) bool {
		if allEvents[i].AgentID != allEvents[j].AgentID {
			return allEvents[i].AgentID < allEvents[j].AgentID
		}
		return allEvents[i].Timestamp < allEvents[j].Timestamp
	})

	// Write compacted daily file
	partitionKey := fmt.Sprintf("%s/%s/compacted", tenantID, date)
	fileResult, err := c.writer.WriteBatch(ctx, allEvents, partitionKey)
	if err != nil {
		return fmt.Errorf("write compacted: %w", err)
	}

	// Atomic manifest commit: add daily file, mark hourly files as superseded
	now := time.Now().UnixMicro()
	dailyFile := storage.ParquetFileRecord{
		FileID:           uuid.New().String(),
		Path:             fileResult.Path,
		TenantID:         tenantID,
		Level:            1,
		MinTimestampUs:   fileResult.MinTimestampUs,
		MaxTimestampUs:   fileResult.MaxTimestampUs,
		MinEventID:       fileResult.MinEventID,
		MaxEventID:       fileResult.MaxEventID,
		RowCount:         fileResult.RowCount,
		CompressedSize:   fileResult.CompressedSize,
		UncompressedSize: fileResult.UncompressedSize,
		SHA256:           fileResult.SHA256,
		Compression:      "zstd",
		SchemaVersion:    1,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	c.manifest.Transaction(ctx, func(tx *sql.Tx) error {
		if err := c.manifest.AddFile(ctx, dailyFile); err != nil {
			return fmt.Errorf("add daily: %w", err)
		}
		for _, f := range files {
			if err := c.manifest.UpdateFileStatus(ctx, f.FileID, "superseded"); err != nil {
				return fmt.Errorf("supersede %s: %w", f.FileID, err)
			}
		}
		return nil
	})

	log.Printf("[tse] compacted %s/%s files=%d events=%d size=%s",
		tenantID, date, len(files), fileResult.RowCount, formatBytes(fileResult.CompressedSize))
	return nil
}

// CleanupSuperseded deletes superseded files from disk after the grace period.
func (c *Compactor) CleanupSuperseded(ctx context.Context) error {
	files, err := c.manifest.FilesFor(ctx, "", 0, 0, "superseded")
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-c.grace).UnixMicro()
	for _, f := range files {
		if f.MaxTS < cutoff {
			if err := os.Remove(f.Path); err != nil && !os.IsNotExist(err) {
				log.Printf("[compactor] remove superseded: %v", err)
			}
			c.manifest.UpdateFileStatus(ctx, f.FileID, "deleted")
		}
	}
	return nil
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%dB", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%dKB", b/1024)
	}
	return fmt.Sprintf("%dMB", b/(1024*1024))
}
