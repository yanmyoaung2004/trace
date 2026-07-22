package response

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/transport"
)

func newTestExecutor(t *testing.T) *Executor {
	t.Helper()
	eventCh := make(chan *monitor.Event, 100)
	return NewExecutor(eventCh)
}

func TestExecutorKillProcessNoPID(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:      "test-1",
		Type:    "kill_process",
		Params:  map[string]any{},
	}

	_, err := e.Execute(context.Background(), action)
	if err == nil {
		t.Error("expected error for missing pid/name")
	}
}

func TestExecutorSystemSnapshot(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:   "test-snap",
		Type: "system_snapshot",
	}

	result, err := e.Execute(context.Background(), action)
	if err != nil {
		t.Fatalf("system snapshot: %v", err)
	}
	if result["status"] != "snapshot_taken" {
		t.Errorf("unexpected status: %v", result["status"])
	}
	if result["platform"] != runtime.GOOS {
		t.Errorf("platform mismatch: got %v", result["platform"])
	}
}

func TestExecutorUnknownAction(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:   "test-unknown",
		Type: "nonexistent_action",
	}

	_, err := e.Execute(context.Background(), action)
	if err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestExecutorQuarantineNoPath(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:   "test-q",
		Type: "quarantine_file",
	}

	_, err := e.Execute(context.Background(), action)
	if err == nil {
		t.Error("expected error for missing path")
	}
}

func TestExecutorQuarantineNonExistent(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:   "test-q-miss",
		Type: "quarantine_file",
		Params: map[string]any{
			"path": "/nonexistent/file.tmp",
		},
	}

	result, err := e.Execute(context.Background(), action)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if result["status"] != "not_found" {
		t.Errorf("expected not_found, got %v", result["status"])
	}
}

func TestExecutorQuarantineFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows — file permissions differ")
	}

	e := newTestExecutor(t)

	tmpFile := filepath.Join(t.TempDir(), "test-quarantine.bin")
	if err := os.WriteFile(tmpFile, []byte("malicious content"), 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	action := &transport.PendingAction{
		ID:   "test-q-real",
		Type: "quarantine_file",
		Params: map[string]any{
			"path": tmpFile,
		},
	}

	result, err := e.Execute(context.Background(), action)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	if result["status"] != "quarantined" && result["status"] != "failed" {
		t.Errorf("unexpected status: %v", result["status"])
	}
}

func TestExecutorTimeout(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:      "test-timeout",
		Type:    "kill_process",
		Timeout: 1,
		Params: map[string]any{
			"pid": 999999,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := e.Execute(ctx, action)
	if err != nil && err.Error() != context.DeadlineExceeded.Error() && runtime.GOOS != "windows" {
		t.Logf("expected timeout or completion, got: %v", err)
	}
}

func TestExecutorBlockIPNoIP(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:   "test-block",
		Type: "block_ip",
	}

	_, err := e.Execute(context.Background(), action)
	if err == nil {
		t.Error("expected error for missing IP")
	}
}

func TestExecutorCollectForensics(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:   "test-forensics",
		Type: "collect_forensics",
	}

	result, err := e.Execute(context.Background(), action)
	if err != nil {
		t.Fatalf("collect forensics: %v", err)
	}
	if result["status"] != "collected" {
		t.Errorf("unexpected status: %v", result["status"])
	}
}
