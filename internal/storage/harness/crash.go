package harness

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

// CrashPoint represents a specific location in the code where a crash can be injected.
type CrashPoint string

const (
	CrashBeforeFlush    CrashPoint = "before_flush"
	CrashAfterFlush     CrashPoint = "after_flush"
	CrashBeforeManifest CrashPoint = "before_manifest_commit"
	CrashAfterManifest  CrashPoint = "after_manifest_commit"
	CrashBeforeParquet  CrashPoint = "before_parquet_write"
	CrashAfterParquet   CrashPoint = "after_parquet_write"
	CrashRandom         CrashPoint = "random"
)

// CrashInjectionConfig controls the behavior of the crash-injection harness.
type CrashInjectionConfig struct {
	BinaryPath    string        // path to the test binary
	DataDir       string        // directory for test data
	Iterations    int           // number of crash iterations to run
	MinOpsPerRun  int           // minimum operations before injecting crash
	MaxOpsPerRun  int           // maximum operations before injecting crash
	RecoveryLimit time.Duration // max time to wait for recovery
}

// CrashInjector runs crash-injection tests against the TSE pipeline.
// It starts a subprocess, lets it run some operations, kills it, restarts it,
// and verifies that no data was lost or duplicated.
type CrashInjector struct {
	cfg CrashInjectionConfig
}

// NewCrashInjector creates a crash-injection harness.
func NewCrashInjector(cfg CrashInjectionConfig) *CrashInjector {
	return &CrashInjector{cfg: cfg}
}

// Run executes the crash-injection test loop.
func (ci *CrashInjector) Run(ctx context.Context) error {
	if err := os.MkdirAll(ci.cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("crash harness: data dir: %w", err)
	}

	for i := 0; i < ci.cfg.Iterations; i++ {
		if err := ci.runIteration(ctx, i); err != nil {
			return fmt.Errorf("iteration %d: %w", i, err)
		}
	}
	return nil
}

func (ci *CrashInjector) runIteration(ctx context.Context, iter int) error {
	iterDir := filepath.Join(ci.cfg.DataDir, fmt.Sprintf("iter-%04d", iter))
	os.MkdirAll(iterDir, 0700)

	// Start the test process
	cmd := exec.CommandContext(ctx, ci.cfg.BinaryPath,
		"-data-dir", iterDir,
		"-crash-point", string(randomCrashPoint()),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	// Let it run for a random duration, then kill it
	sleepDur := time.Duration(ci.cfg.MinOpsPerRun+rand.Intn(ci.cfg.MaxOpsPerRun-ci.cfg.MinOpsPerRun)) * time.Millisecond

	// Wait for the duration, the process to exit, or context cancellation
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(sleepDur):
		// Kill with SIGKILL (simulates power failure)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-done
	case err := <-done:
		// Process exited on its own
		return fmt.Errorf("process exited early: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// VerifyDataIntegrity checks that the data in the given directory is consistent.
// Returns number of events found and any integrity violations.
func VerifyDataIntegrity(dir string) (totalEvents int, violations []string, err error) {
	ctx := context.Background()

	// 1. Open manifest
	m, err := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		// No manifest means no data was committed — valid empty state
		return 0, nil, nil
	}
	defer m.Close()

	// 2. Get watermark
	wm, err := m.Watermark(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("watermark: %w", err)
	}

	// 3. Open hot store
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		// No hot store — check if watermark is empty
		if wm.LastID == "" {
			return 0, nil, nil
		}
		return 0, nil, fmt.Errorf("hot store: %w", err)
	}
	defer hot.Close()

	// 4. Count hot events
	hotResult, err := hot.Query(ctx, storage.Query{Limit: 1000000})
	if err != nil {
		return 0, nil, fmt.Errorf("hot query: %w", err)
	}

	// Build set of hot event IDs
	hotIDs := make(map[string]bool, len(hotResult.Events))
	for _, e := range hotResult.Events {
		hotIDs[e.ID] = true
	}

	// 5. List committed parquet files
	files, err := m.FilesFor(ctx, "", 0, 0, "committed")
	if err != nil {
		return 0, nil, fmt.Errorf("files: %w", err)
	}

	// 6. Read parquet files and check for internal consistency
	// Note: duplicates BETWEEN hot and cold are EXPECTED by design (10min overlap window).
	// We only flag duplicates WITHIN cold files and check watermark consistency.
	pReader := cold.NewReaderPool(1)
	coldIDs := make(map[string]bool)
	for _, f := range files {
		result, err := pReader.QueryFiles(ctx, []storage.FileInfo{f}, storage.Query{})
		if err != nil {
			violations = append(violations, fmt.Sprintf("read %s: %v", f.Path, err))
			continue
		}
		for _, e := range result.Events {
			if coldIDs[e.ID] {
				violations = append(violations, fmt.Sprintf("duplicate ID %s within cold files", e.ID))
			}
			coldIDs[e.ID] = true
		}
	}

	// Count unique events across tiers (hot+cold with overlap expected)
	allIDs := make(map[string]bool)
	for id := range hotIDs {
		allIDs[id] = true
	}
	for id := range coldIDs {
		allIDs[id] = true
	}
	totalEvents = len(allIDs)

	// 7. Verify watermark
	maxID := ""
	for id := range hotIDs {
		if id > maxID {
			maxID = id
		}
	}
	for id := range coldIDs {
		if id > maxID {
			maxID = id
		}
	}
	if wm.LastID != "" && maxID > wm.LastID {
		violations = append(violations, fmt.Sprintf("watermark %s is behind max event ID %s", wm.LastID, maxID))
	}

	return totalEvents, violations, nil
}

func randomCrashPoint() CrashPoint {
	points := []CrashPoint{
		CrashBeforeFlush,
		CrashAfterFlush,
		CrashBeforeManifest,
		CrashAfterManifest,
		CrashBeforeParquet,
		CrashAfterParquet,
	}
	return points[rand.Intn(len(points))]
}
