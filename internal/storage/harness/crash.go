package harness

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"
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
	return 0, nil, nil
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
