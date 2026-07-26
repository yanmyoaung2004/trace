package edr_agent

import (
	"context"
	"testing"
	"time"
)

func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	a := New(&Config{
		ServerURL: "https://example.com",
		APIKey:    "test-key",
		DataDir:   t.TempDir(),
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		a.Stop(ctx)
	})
	return a
}

func TestAgentNew(t *testing.T) {
	a := newTestAgent(t)
	if a == nil {
		t.Fatal("expected non-nil agent")
	}
}

func TestAgentHostname(t *testing.T) {
	a := newTestAgent(t)
	if a.hostname == "" {
		t.Error("expected non-empty hostname")
	}
}
