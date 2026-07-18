package response_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/db"
	"github.com/yanmyoaung2004/trace/internal/response"
)

func setupResponse(t *testing.T) *response.Agent {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	return response.New(database.DB)
}

func TestBlockIPNoIP(t *testing.T) {
	agent := setupResponse(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "block_ip",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if _, ok := output["error"]; !ok {
		t.Fatal("expected error for missing IP")
	}
}

func TestBlockIPRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OS command test in short mode")
	}
	agent := setupResponse(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "block_ip",
		"ip":     "10.0.0.99",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	actionID, ok := output["action_id"].(string)
	if !ok || actionID == "" {
		t.Fatal("expected action_id")
	}

	status, _ := output["status"].(string)
	if status == "" {
		t.Fatal("expected status")
	}

	if _, ok := output["rollback_command"]; !ok {
		t.Fatal("expected rollback_command")
	}
}

func TestQuarantineFileMissing(t *testing.T) {
	agent := setupResponse(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "quarantine_file",
		"path":   "C:\\nonexistent\\file.txt",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if _, ok := output["error"]; !ok {
		t.Fatal("expected error for missing file")
	}
}

func TestKillProcessNoTarget(t *testing.T) {
	agent := setupResponse(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "kill_process",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if _, ok := output["error"]; !ok {
		t.Fatal("expected error for missing target")
	}
}

func TestKillProcessByName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OS command test in short mode")
	}
	agent := setupResponse(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "kill_process",
		"name":   "nonexistent_process_xyz",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	status, _ := output["status"].(string)
	if status == "" {
		t.Fatal("expected status")
	}

	actionID, _ := output["action_id"].(string)
	if actionID == "" {
		t.Fatal("expected action_id")
	}
}

func TestRestartService(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OS command test in short mode")
	}
	agent := setupResponse(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "restart_service",
		"name":   "BITS",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	status, _ := output["status"].(string)
	if status == "" {
		t.Fatal("expected status")
	}
}

func TestRollbackNotFound(t *testing.T) {
	agent := setupResponse(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action":    "rollback",
		"action_id": "nonexistent-id",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if _, ok := output["error"]; !ok {
		t.Fatal("expected error for missing action")
	}
}

func TestAllActionsReturnActionID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OS command execution test in short mode")
	}
	agent := setupResponse(t)
	ctx := context.Background()

	actions := []map[string]any{
		{"action": "block_ip", "ip": "10.0.0.1"},
		{"action": "kill_process", "name": "test"},
		{"action": "restart_service", "name": "test"},
	}

	for _, input := range actions {
		output, err := agent.Execute(ctx, input)
		if err != nil {
			t.Fatalf("Execute %v failed: %v", input, err)
		}

		id, _ := output["action_id"].(string)
		if id == "" {
			t.Fatalf("expected action_id for %v", input)
		}
	}
}

func TestName(t *testing.T) {
	agent := setupResponse(t)
	if agent.Name() != "response" {
		t.Fatalf("expected 'response', got %s", agent.Name())
	}
}

func TestCapabilitiesNotEmpty(t *testing.T) {
	agent := setupResponse(t)
	caps := agent.Capabilities()
	if len(caps) == 0 {
		t.Fatal("expected capabilities")
	}

	expected := map[string]bool{
		"block_ip":         false,
		"quarantine_file":  false,
		"kill_process":     false,
		"restart_service":  false,
		"rollback":         false,
	}

	for _, c := range caps {
		expected[c.Action] = true
	}

	for action, found := range expected {
		if !found {
			t.Fatalf("missing capability: %s", action)
		}
	}
}
