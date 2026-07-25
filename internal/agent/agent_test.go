package agent

import (
	"context"
	"testing"
)

type mockAgent struct{}

func (m *mockAgent) Name() string { return "mock" }
func (m *mockAgent) Execute(ctx context.Context, input Input) (Output, error) {
	return Output{"result": "ok", "success": true}, nil
}
func (m *mockAgent) Capabilities() []Capability {
	return []Capability{{Action: "mock_action", Inputs: []string{"param"}, Outputs: []string{"result"}}}
}

func TestAgentInterface(t *testing.T) {
	var a Agent = &mockAgent{}
	if a.Name() != "mock" {
		t.Errorf("name = %q", a.Name())
	}

	caps := a.Capabilities()
	if len(caps) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(caps))
	}
	if caps[0].Action != "mock_action" {
		t.Errorf("action = %q", caps[0].Action)
	}

	out, err := a.Execute(context.Background(), Input{"action": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if out["success"] != true {
		t.Error("expected success")
	}
	if out["result"] != "ok" {
		t.Errorf("result = %v", out["result"])
	}
}

func TestInput(t *testing.T) {
	input := Input{"key": "value", "count": 42}
	if input["key"] != "value" {
		t.Errorf("input key = %v", input["key"])
	}
	if input["count"] != 42 {
		t.Errorf("input count = %v", input["count"])
	}
}

func TestCapabilityStructure(t *testing.T) {
	c := Capability{
		Action:  "test",
		Inputs:  []string{"a", "b"},
		Outputs: []string{"c"},
	}
	if c.Action != "test" {
		t.Errorf("action = %q", c.Action)
	}
	if len(c.Inputs) != 2 {
		t.Errorf("expected 2 inputs, got %d", len(c.Inputs))
	}
}

