package harness

import (
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func buildTestBinary(t *testing.T) string {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "tse-crash-test.exe")
	cmd := exec.Command("go", "build", "-o", binaryPath, "../../../cmd/tse-crash-test/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}
	return binaryPath
}

func runBinary(t *testing.T, binaryPath, dataDir string, ops int) error {
	t.Helper()
	cmd := exec.Command(binaryPath,
		"-data-dir", dataDir,
		"-ops", "50",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("binary output: %s", string(out))
	}
	return err
}

func runBinaryWithKill(t *testing.T, binaryPath, dataDir string, ops int, killDelay time.Duration) {
	t.Helper()
	cmd := exec.Command(binaryPath,
		"-data-dir", dataDir,
		"-ops", "50",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	time.Sleep(killDelay)

	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("kill: %v", err)
		}
	}
	cmd.Wait()
}

func TestCrashRecovery_NormalRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crash test in short mode")
	}

	binaryPath := buildTestBinary(t)
	dataDir := t.TempDir()

	if err := runBinary(t, binaryPath, dataDir, 50); err != nil {
		t.Fatal(err)
	}

	total, violations, err := VerifyDataIntegrity(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if total < 50 {
		t.Errorf("expected at least 50 events, got %d", total)
	}
	if len(violations) > 0 {
		t.Errorf("integrity violations: %v", violations)
	}
}

func TestCrashRecovery_KillDuringWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crash test in short mode")
	}

	binaryPath := buildTestBinary(t)
	dataDir := t.TempDir()

	// Kill the process after 300ms (mid-way through writes)
	runBinaryWithKill(t, binaryPath, dataDir, 50, 300*time.Millisecond)

	// Run again to recover
	if err := runBinary(t, binaryPath, dataDir, 50); err != nil {
		t.Fatal(err)
	}

	// Verify integrity
	total, violations, err := VerifyDataIntegrity(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if total < 50 {
		t.Errorf("expected at least 50 events after recovery, got %d", total)
	}
	if len(violations) > 0 {
		t.Errorf("integrity violations after crash recovery: %v", violations)
	}
}

func TestCrashRecovery_KillDuringFlush(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crash test in short mode")
	}

	binaryPath := buildTestBinary(t)
	dataDir := t.TempDir()

	// First run writes 50 events
	if err := runBinary(t, binaryPath, dataDir, 50); err != nil {
		t.Fatal(err)
	}

	total1, v1, err := VerifyDataIntegrity(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first run: %d events", total1)
	if len(v1) > 0 {
		t.Errorf("first run violations: %v", v1)
	}

	// Second run writes 50 more, kill during flush/parquet write
	runBinaryWithKill(t, binaryPath, dataDir, 100, 200*time.Millisecond)

	// Recover
	if err := runBinary(t, binaryPath, dataDir, 100); err != nil {
		t.Fatal(err)
	}

	total2, v2, err := VerifyDataIntegrity(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if total2 < total1 {
		t.Errorf("data loss: had %d events, now %d", total1, total2)
	}
	if len(v2) > 0 {
		t.Errorf("integrity violations after second crash: %v", v2)
	}
}

func TestCrashRecovery_RepeatedKills(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping crash test in short mode")
	}

	binaryPath := buildTestBinary(t)
	dataDir := t.TempDir()

	var lastTotal int

	for i := 0; i < 5; i++ {
		killDelay := time.Duration(100+50*i) * time.Millisecond
		runBinaryWithKill(t, binaryPath, dataDir, 50, killDelay)

		// Recover
		if err := runBinary(t, binaryPath, dataDir, 50); err != nil {
			t.Fatalf("iteration %d recovery: %v", i, err)
		}

		total, violations, err := VerifyDataIntegrity(dataDir)
		if err != nil {
			t.Fatalf("iteration %d verify: %v", i, err)
		}
		if total < lastTotal {
			t.Errorf("iteration %d: data loss: %d -> %d", i, lastTotal, total)
		}
		if len(violations) > 0 {
			t.Errorf("iteration %d violations: %v", i, violations)
		}
		lastTotal = total
	}
}
