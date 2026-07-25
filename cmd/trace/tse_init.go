package main

import (
	"context"
	"log"
	"time"

	"github.com/yanmyoaung2004/trace/internal/config"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	"github.com/yanmyoaung2004/trace/internal/storage/gc"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/router"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// TSE holds the initialized Trace Storage Engine components.
type TSE struct {
	Hot      *sqlite.SQLiteHotStore
	Manifest *manifestpkg.Manifest
	Parquet  *parquet.ParquetWriter
	Flusher  *flusher.Flusher
	GC       *gc.GC
	Router   *router.Router
	Reader   cold.ColdReader
	Ctx      context.Context
	Cancel   context.CancelFunc
}

// initTSE initializes the Trace Storage Engine from config.
func initTSE(cfg *config.TSEConfig) (*TSE, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	storagePath := cfg.StoragePath

	// Create directories
	hotPath := storagePath + "/hot.db"
	manifestPath := storagePath + "/manifest.db"
	eventsDir := storagePath + "/events"
	tempDir := storagePath + "/temp"

	// SQLite hot store
	hot, err := sqlite.NewSQLiteHotStore(hotPath)
	if err != nil {
		return nil, err
	}

	// Manifest
	m, err := manifestpkg.NewManifest(manifestPath)
	if err != nil {
		hot.Close()
		return nil, err
	}

	// Parquet writer
	parquetOpts := parquet.DefaultParquetOptions()
	if cfg.Compression != "" {
		parquetOpts.Compression = cfg.Compression
	}
	pw := parquet.NewParquetWriter(tempDir, eventsDir, parquetOpts)

	// Cold reader (pooled to bound goroutine leaks from xitongsys/parquet-go)
	cr := cold.NewReaderPool(cold.DefaultMaxConcurrent)

	// Router
	r := router.NewRouter(hot, cr, m)

	// Flusher
	flushInterval := 30 * time.Second
	if cfg.FlushInterval != "" {
		if d, err := time.ParseDuration(cfg.FlushInterval); err == nil {
			flushInterval = d
		}
	}

	f := flusher.NewFlusher(hot, m, pw, flushInterval, 256<<20, 100000, eventsDir)

	g := gc.NewGC(m, storagePath, 24*time.Hour)
	if cfg.ColdTTL != "" {
		if d, err := time.ParseDuration(cfg.ColdTTL); err == nil && d > 0 {
			g.WithColdTTL(d)
		}
	}

	// Check disk at startup
	if du, err := storage.CheckDisk(storagePath); err == nil {
		log.Printf("[tse] disk: %d/%d GB (%.0f%%)",
			(du.TotalBytes-du.FreeBytes)/1073741824,
			du.TotalBytes/1073741824,
			du.UsedRatio*100)
		if storage.IsDiskWarning(du) {
			log.Printf("[tse] WARNING: disk usage >%.0f%%", storage.DiskWarnRatio*100)
		}
		if storage.IsDiskFull(du) {
			log.Printf("[tse] CRITICAL: disk usage >%.0f%%", storage.DiskFullRatio*100)
		}
	} else {
		log.Printf("[tse] disk check unavailable: %v", err)
	}

	// Register disk check for Prometheus /metrics
	metrics.SetDiskChecker(func() *metrics.DiskInfo {
		du, err := storage.CheckDisk(storagePath)
		if err != nil {
			return nil
		}
		return &metrics.DiskInfo{
			TotalBytes: du.TotalBytes,
			FreeBytes:  du.FreeBytes,
			UsedRatio:  du.UsedRatio,
		}
	})

	// Run orphan cleanup at startup
	manifestpkg.OrphanGC(context.Background(), storagePath, m)

	ctx, cancel := context.WithCancel(context.Background())

	log.Printf("[tse] initialized (hot=%s, events=%s, compression=%s)", hotPath, eventsDir, parquetOpts.Compression)

	return &TSE{
		Hot:      hot,
		Manifest: m,
		Parquet:  pw,
		Flusher:  f,
		GC:       g,
		Router:   r,
		Reader:   cr,
		Ctx:      ctx,
		Cancel:   cancel,
	}, nil
}

// StartTSE starts the TSE background tasks (flusher, GC).
func (t *TSE) StartTSE() {
	if t == nil {
		return
	}
	go t.Flusher.Run(t.Ctx)
	go t.GC.Run(t.Ctx)
	log.Printf("[tse] flusher+GC started")
}

// StopTSE gracefully shuts down the TSE pipeline.
func (t *TSE) StopTSE() {
	if t == nil {
		return
	}
	t.Cancel()
	t.Hot.Close()
	t.Manifest.Close()
	t.Parquet.Close()
	log.Printf("[tse] stopped")
}
