package plugin

import (
	"context"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type mockAgent struct{ name string }

func (m *mockAgent) Name() string { return m.name }
func (m *mockAgent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	return agent.Output{}, nil
}
func (m *mockAgent) Capabilities() []agent.Capability { return nil }

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
	if len(r.List()) != 0 {
		t.Errorf("expected empty registry, got %d agents", len(r.List()))
	}
}

func TestRegister(t *testing.T) {
	r := NewRegistry()
	a := &mockAgent{name: "test-agent"}
	r.Register(a)

	agents := r.List()
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].Name() != "test-agent" {
		t.Errorf("name = %q, want test-agent", agents[0].Name())
	}
}

func TestRegister_Duplicate(t *testing.T) {
	r := NewRegistry()
	a := &mockAgent{name: "dup"}
	r.Register(a)
	r.Register(a) // should not panic or double-count

	agents := r.List()
	if len(agents) != 1 {
		t.Errorf("expected 1 agent after duplicate register, got %d", len(agents))
	}
}

func TestGet(t *testing.T) {
	r := NewRegistry()
	a := &mockAgent{name: "my-agent"}
	r.Register(a)

	got := r.Get("my-agent")
	if got == nil {
		t.Fatal("expected to find agent")
	}
	if got.Name() != "my-agent" {
		t.Errorf("name = %q", got.Name())
	}
}

func TestGet_NotFound(t *testing.T) {
	r := NewRegistry()
	got := r.Get("nonexistent")
	if got != nil {
		t.Error("expected nil for nonexistent agent")
	}
}

func TestMultipleAgents(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockAgent{name: "a"})
	r.Register(&mockAgent{name: "b"})
	r.Register(&mockAgent{name: "c"})

	agents := r.List()
	if len(agents) != 3 {
		t.Errorf("expected 3 agents, got %d", len(agents))
	}
}
