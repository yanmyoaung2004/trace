package edr_agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "trace-agent-test-"+t.Name())
	os.MkdirAll(dir, 0700)
	a := New(&Config{
		ServerURL: "https://example.com",
		APIKey:    "test-key",
		DataDir:   dir,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		a.Stop(ctx)
		time.Sleep(200 * time.Millisecond) // let goroutines release DB handles
		os.RemoveAll(dir)
	})
	return a, dir
}

func TestAgentNew(t *testing.T) {
	a, _ := newTestAgent(t)
	if a == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestAgentHostname(t *testing.T) {
	a, _ := newTestAgent(t)
	if a.hostname == "" {
		t.Error("expected non-empty hostname")
	}
}
