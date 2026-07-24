package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

var (
	dataDir   = flag.String("data-dir", "", "TSE data directory")
	ops       = flag.Int("ops", 100, "number of events to write")
	crashPoint = flag.String("crash-point", "", "crash point to inject (or empty for no crash)")
)

func main() {
	flag.Parse()
	if *dataDir == "" {
		log.Fatal("-data-dir is required")
	}

	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(*dataDir, "hot.db"))
	if err != nil {
		return fmt.Errorf("hot store: %w", err)
	}
	defer hot.Close()

	m, err := manifestpkg.NewManifest(filepath.Join(*dataDir, "manifest.db"))
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	defer m.Close()

	pw := parquet.NewParquetWriter(
		filepath.Join(*dataDir, "temp"),
		filepath.Join(*dataDir, "events"),
		parquet.DefaultParquetOptions(),
	)
	defer pw.Close()

	f := flusher.NewFlusher(hot, m, pw, 100*time.Millisecond, 100, 10000, filepath.Join(*dataDir, "events"))

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	go f.Run(ctx2)
	time.Sleep(50 * time.Millisecond)

	// Write events in batches
	numBatches := (*ops + 9) / 10
	for batch := 0; batch < numBatches; batch++ {
		start := batch * 10
		end := start + 10
		if end > *ops {
			end = *ops
		}

		events := make([]*storage.Event, 0, end-start)
		for i := start; i < end; i++ {
			events = append(events, &storage.Event{
				ID:        uuidV7ish(i),
				TenantID:  "crash-test",
				AgentID:   fmt.Sprintf("agent-%d", i%5),
				Timestamp: time.Now().UnixMicro(),
				EventType: "crash_test",
				Severity:  rand.Intn(5) + 1,
			})
		}

		if err := hot.WriteBatch(ctx, events); err != nil {
			return fmt.Errorf("write batch %d: %w", batch, err)
		}

		// Inject crash at midpoint
		if *crashPoint == "after_write" && batch == numBatches/2 {
			log.Printf("[crash] injecting crash after write batch %d", batch)
			os.Exit(137)
		}
	}

	// Wait for flusher
	time.Sleep(500 * time.Millisecond)

	if *crashPoint == "after_flush" {
		log.Printf("[crash] injecting crash after flush")
		os.Exit(137)
	}

	// Trigger explicit flush
	if err := f.FlushNow(ctx); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	if *crashPoint == "after_manifest_commit" {
		log.Printf("[crash] injecting crash after manifest commit")
		os.Exit(137)
	}

	log.Printf("[crash-test] completed successfully: %d events written", *ops)
	return nil
}

func uuidV7ish(i int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
}
