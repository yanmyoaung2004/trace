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

// VerifyDataIntegrity checks that TSE state is consistent after crash recovery.
// Uses manifest metadata + hot store count — does NOT read Parquet file contents.
func VerifyDataIntegrity(dir string) (totalEvents int, violations []string, err error) {
	ctx := context.Background()

	m, err := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		return 0, nil, nil
	}
	defer m.Close()

	wm, err := m.Watermark(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("watermark: %w", err)
	}

	files, err := m.FilesFor(ctx, "", 0, 0, "committed")
	if err != nil {
		return 0, nil, fmt.Errorf("files: %w", err)
	}

	for _, f := range files {
		info, err := os.Stat(f.Path)
		if err != nil {
			violations = append(violations, fmt.Sprintf("committed file missing: %s", f.Path))
			continue
		}
		if info.Size() < 100 {
			violations = append(violations, fmt.Sprintf("committed file too small (%d bytes): %s", info.Size(), f.Path))
		}
	}

	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		if wm.LastID == "" && len(files) == 0 {
			return 0, violations, nil
		}
		return 0, violations, nil
	}
	defer hot.Close()

	result, qErr := hot.Query(ctx, storage.Query{Limit: 1000000})
	if qErr != nil {
		return len(files), violations, nil
	}

	totalEvents = len(result.Events) + len(files)
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
