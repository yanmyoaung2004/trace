package main

import (
	"context"
	"log"
	"time"

	"github.com/yanmyoaung2004/trace/internal/config"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
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

	// Cold reader
	cr := cold.NewParquetReader()

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

	ctx, cancel := context.WithCancel(context.Background())

	log.Printf("[tse] initialized (hot=%s, events=%s, compression=%s)", hotPath, eventsDir, parquetOpts.Compression)

	return &TSE{
		Hot:      hot,
		Manifest: m,
		Parquet:  pw,
		Flusher:  f,
		Router:   r,
		Reader:   cr,
		Ctx:      ctx,
		Cancel:   cancel,
	}, nil
}

// StartTSE starts the TSE background tasks (flusher, etc.).
func (t *TSE) StartTSE() {
	if t == nil {
		return
	}
	go t.Flusher.Run(t.Ctx)
	log.Printf("[tse] flusher started")
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
