package playbook_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/agent"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/db"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/investigation"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/playbook"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/plugin"
)

type mockAgent struct {
	name         string
	capabilities []agent.Capability
	execFn       func(ctx context.Context, input agent.Input) (agent.Output, error)
}

func (m *mockAgent) Name() string                          { return m.name }
func (m *mockAgent) Capabilities() []agent.Capability      { return m.capabilities }
func (m *mockAgent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	return m.execFn(ctx, input)
}

func setupExecutor(t *testing.T) (*playbook.Executor, *investigation.Manager, *plugin.Registry) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	invMgr := investigation.NewManager(database)
	logWriter, _ := investigation.NewLogWriter(filepath.Join(dir, "logs"))
	reg := plugin.NewRegistry()

	reg.Register(&mockAgent{
		name: "test-agent",
		capabilities: []agent.Capability{
			{Action: "test_action", Inputs: []string{"value"}, Outputs: []string{"result"}},
		},
		execFn: func(ctx context.Context, input agent.Input) (agent.Output, error) {
			return agent.Output{
				"result": "processed: " + input["value"].(string),
			}, nil
		},
	})

	exec := playbook.NewExecutor(reg, invMgr, logWriter)
	return exec, invMgr, reg
}

func TestExecutorBasic(t *testing.T) {
	exec, invMgr, _ := setupExecutor(t)
	ctx := context.Background()

	inv, _ := invMgr.Create(ctx, "test intent", "test-pb")

	pb := &playbook.Playbook{
		Name: "test-pb",
		Steps: []playbook.Step{
			{Agent: "test-agent", Action: "test_action", Params: map[string]any{"value": "${input.query}"}},
		},
	}

	input := map[string]any{"query": "hello"}
	results, err := exec.Execute(ctx, inv, pb, input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	key := "test-agent.test_action"
	output, ok := results[key]
	if !ok {
		t.Fatalf("result key %s not found", key)
	}

	outputMap := output.(map[string]any)
	if outputMap["result"] != "processed: hello" {
		t.Fatalf("unexpected result: %v", outputMap["result"])
	}
}

func TestExecutorConditional(t *testing.T) {
	exec, invMgr, reg := setupExecutor(t)
	ctx := context.Background()

	secondCalled := false
	reg.Register(&mockAgent{
		name: "second-agent",
		execFn: func(ctx context.Context, input agent.Input) (agent.Output, error) {
			secondCalled = true
			return agent.Output{"done": true}, nil
		},
	})

	inv, _ := invMgr.Create(ctx, "conditional test", "cond-pb")

	pb := &playbook.Playbook{
		Name: "cond-pb",
		Steps: []playbook.Step{
			{Agent: "test-agent", Action: "test_action", Params: map[string]any{"value": "first"}},
			{
				Agent:  "second-agent",
				Action: "test_action",
				If:     `${result.unknown_field} != ""`,
				Params: map[string]any{"value": "second"},
			},
		},
	}

	_, err := exec.Execute(ctx, inv, pb, map[string]any{"query": "x"})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if secondCalled {
		t.Fatal("second step should have been skipped")
	}
}

func TestExecutorOptional(t *testing.T) {
	exec, invMgr, _ := setupExecutor(t)
	ctx := context.Background()

	inv, _ := invMgr.Create(ctx, "optional test", "opt-pb")

	pb := &playbook.Playbook{
		Name: "opt-pb",
		Steps: []playbook.Step{
			{
				Agent:    "nonexistent",
				Action:   "missing",
				Optional: true,
				Params:   map[string]any{},
			},
			{Agent: "test-agent", Action: "test_action", Params: map[string]any{"value": "ok"}},
		},
	}

	_, err := exec.Execute(ctx, inv, pb, map[string]any{"query": "x"})
	if err != nil {
		t.Fatalf("Execute with optional step should not fail: %v", err)
	}
}

func TestExecutorNonOptionalFails(t *testing.T) {
	exec, invMgr, _ := setupExecutor(t)
	ctx := context.Background()

	inv, _ := invMgr.Create(ctx, "fail test", "fail-pb")

	pb := &playbook.Playbook{
		Name: "fail-pb",
		Steps: []playbook.Step{
			{
				Agent:    "nonexistent",
				Action:   "missing",
				Optional: false,
				Params:   map[string]any{},
			},
		},
	}

	_, err := exec.Execute(ctx, inv, pb, map[string]any{})
	if err == nil {
		t.Fatal("expected error for non-optional step with missing agent")
	}
}

func TestExecutorTimeout(t *testing.T) {
	exec, invMgr, reg := setupExecutor(t)
	ctx := context.Background()

	reg.Register(&mockAgent{
		name: "slow-agent",
		execFn: func(ctx context.Context, input agent.Input) (agent.Output, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})

	inv, _ := invMgr.Create(ctx, "timeout test", "time-pb")

	pb := &playbook.Playbook{
		Name: "time-pb",
		Steps: []playbook.Step{
			{
				Agent:   "slow-agent",
				Action:  "hang",
				Timeout: "100ms",
				Params:  map[string]any{},
			},
		},
	}

	_, err := exec.Execute(ctx, inv, pb, map[string]any{})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestExecutorMultipleSteps(t *testing.T) {
	exec, invMgr, _ := setupExecutor(t)
	ctx := context.Background()

	inv, _ := invMgr.Create(ctx, "multi step", "multi-pb")

	pb := &playbook.Playbook{
		Name: "multi-pb",
		Steps: []playbook.Step{
			{Agent: "test-agent", Action: "test_action", Params: map[string]any{"value": "step1"}},
		},
	}

	results, err := exec.Execute(ctx, inv, pb, map[string]any{"query": "multi"})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestExecutorInvestigationStatus(t *testing.T) {
	exec, invMgr, _ := setupExecutor(t)
	ctx := context.Background()

	inv, _ := invMgr.Create(ctx, "status test", "status-pb")

	pb := &playbook.Playbook{
		Name: "status-pb",
		Steps: []playbook.Step{
			{Agent: "test-agent", Action: "test_action", Params: map[string]any{"value": "done"}},
		},
	}

	_, err := exec.Execute(ctx, inv, pb, map[string]any{})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	updated, err := invMgr.Get(ctx, inv.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if updated.Status != "completed" {
		t.Fatalf("expected status completed, got %s", updated.Status)
	}
}
