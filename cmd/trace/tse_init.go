package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/yanmyoaung2004/trace/internal/config"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/batch"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	"github.com/yanmyoaung2004/trace/internal/storage/gc"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/queue"
	"github.com/yanmyoaung2004/trace/internal/storage/router"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// s3ConfigFromCfg builds an S3 config from TSE config.
func s3ConfigFromCfg(cfg *config.TSEConfig) *storage.S3Config {
	if cfg.S3Bucket == "" {
		return nil
	}
	return &storage.S3Config{
		Bucket:   cfg.S3Bucket,
		Endpoint: cfg.S3Endpoint,
		Region:   cfg.S3Region,
		UseSSL:   cfg.S3UseSSL,
	}
}

// TSE holds the initialized Trace Storage Engine components.
type TSE struct {
	Hot      *sqlite.SQLiteHotStore
	Manifest *manifestpkg.Manifest
	Parquet  *parquet.ParquetWriter
	Flusher  *flusher.Flusher
	GC       *gc.GC
	Router   *router.Router
	Reader   cold.ColdReader
	Queue    *queue.IngestQueue
	Batch    *batch.BatchWriter
	Writer   *batch.WriterGoroutine
	Leader   *storage.LeaderElector // nil when no S3 configured
	Ctx      context.Context
	Cancel   context.CancelFunc
	bwCtx    context.Context
	bwCancel context.CancelFunc
}

// WriteEvents submits events through the ingest queue for rate-limited processing.
// The queue applies backpressure: channel → spill-to-disk → drop.
// Events are batch-written to SQLite by the background batch writer.
func (t *TSE) WriteEvents(ctx context.Context, events []*storage.Event) error {
	return t.Queue.WriteBatch(ctx, events)
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

	// S3 config
	s3Cfg := s3ConfigFromCfg(cfg)
	var s3Client *storage.S3Client
	if s3Cfg != nil {
		s3Client = storage.NewS3Client(*s3Cfg)
	}

	// Parquet writer
	parquetOpts := parquet.DefaultParquetOptions()
	if cfg.Compression != "" {
		parquetOpts.Compression = cfg.Compression
	}
	if cfg.CompressionLevel > 0 {
		parquetOpts.CompressionLevel = cfg.CompressionLevel
	}
	if cfg.RowGroupSize > 0 {
		parquetOpts.RowGroupSize = cfg.RowGroupSize
	}
	pw := parquet.NewParquetWriter(tempDir, eventsDir, parquetOpts)
	if s3Client != nil {
		pw.SetS3(s3Client)
		log.Printf("[tse] S3 cold storage enabled: s3://%s/%s", cfg.S3Bucket, eventsDir)
	}

	// Cold reader — DuckDB (CGO) or pure Go (auto-selected)
	defaultReader := cold.NewDefaultReader()
	if s3Client != nil {
		if pr, ok := defaultReader.(*cold.ParquetReader); ok {
			pr.SetS3(s3Client)
		}
	}
	cr := cold.NewReaderPool(cold.DefaultMaxConcurrent)
	cr.SetReader(defaultReader)

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

	// Queue with backpressure (spill to disk when full)
	q, err := queue.NewIngestQueue(queue.DefaultQueueCapacity, &queue.DiskSpillConfig{
		Dir:   filepath.Join(storagePath, "spill"),
		Limit: 1 << 30,
	})
	if err != nil {
		return nil, fmt.Errorf("queue: %w", err)
	}

	// Batch writer drains the queue and writes to SQLite in batches
	bw := batch.NewBatchWriter(1000, 250*time.Millisecond)

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

	// Batch writer context (separate from flusher context for independent lifecycle)
	bwCtx, bwCancel := context.WithCancel(context.Background())

	// Leader elector (S3-based, for multi-node active-passive)
	var leader *storage.LeaderElector
	if s3Client != nil {
		role := storage.NodeRoleAuto
		switch cfg.NodeRole {
		case "leader":
			role = storage.NodeRoleLeader
		case "follower":
			role = storage.NodeRoleFollower
		}
		leader = storage.NewLeaderElector(s3Client, role)
	}

	// Register disk check for write rejection and Prometheus metrics
	storage.StoragePathFunc = func() string { return storagePath }
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
		Queue:    q,
		Batch:    bw,
		Leader:   leader,
		Ctx:      ctx,
		Cancel:   cancel,
		bwCtx:    bwCtx,
		bwCancel: bwCancel,
	}, nil
}

// StartTSE starts the TSE background tasks (queue drain, flusher, GC, leader election).
func (t *TSE) StartTSE() {
	if t == nil {
		return
	}

	// Batch writer: drains the ingest queue and writes batches to SQLite
	go t.Batch.Run(t.bwCtx, t.Queue.Dequeue(), t.Hot.WriteBatch)
	log.Printf("[tse] batch writer started")

	// Leader election (multi-node mode)
	if t.Leader != nil {
		go t.Leader.Run(t.Ctx)
		log.Printf("[tse] leader election started (role=%v)", t.Leader.NodeID())
	}

	// Flusher — only runs on the leader in multi-node mode
	if t.Leader == nil || t.Leader.IsLeader() {
		go t.Flusher.Run(t.Ctx)
		log.Printf("[tse] flusher started")
	} else {
		log.Printf("[tse] flusher not started (follower mode)")
	}

	go t.GC.Run(t.Ctx)
	log.Printf("[tse] GC started")
}

// StopTSE gracefully shuts down the TSE pipeline.
func (t *TSE) StopTSE() {
	if t == nil {
		return
	}

	// Stop batch writer first (drains pending queue events)
	t.bwCancel()

	// Signal flusher to stop and wait for in-flight flush to complete
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()
	if err := t.Flusher.Stop(stopCtx); err != nil {
		log.Printf("[tse] flusher stop: %v (forcing close)", err)
	}
	t.Cancel()
	t.Hot.Close()
	t.Manifest.Close()
	t.Parquet.Close()
	log.Printf("[tse] stopped")
}
