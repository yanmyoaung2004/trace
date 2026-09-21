package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/agent"
)

type ActionRecord struct {
	ID              string `json:"id"`
	InvestigationID string `json:"investigation_id"`
	Action          string `json:"action"`
	Target          string `json:"target"`
	Status          string `json:"status"`
	Command         string `json:"command"`
	Output          string `json:"output"`
	RollbackCmd     string `json:"rollback_command"`
	RollbackStatus  string `json:"rollback_status"`
	CreatedAt       string `json:"created_at"`
}

type Agent struct {
	db            *sql.DB
	quarantineDir string
}

func New(database *sql.DB) *Agent {
	qDir := filepath.Join(os.TempDir(), "trace-quarantine")
	os.MkdirAll(qDir, 0700)
	return &Agent{db: database, quarantineDir: qDir}
}

func (a *Agent) Name() string { return "response" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "block_ip", Inputs: []string{"ip"}, Outputs: []string{"status", "command", "rollback_command"}},
		{Action: "quarantine_file", Inputs: []string{"path"}, Outputs: []string{"status", "quarantine_path", "rollback_command"}},
		{Action: "kill_process", Inputs: []string{"name", "pid"}, Outputs: []string{"status", "rollback_command"}},
		{Action: "restart_service", Inputs: []string{"name"}, Outputs: []string{"status", "rollback_command"}},
		{Action: "run_script", Inputs: []string{"script"}, Outputs: []string{"status"}},
		{Action: "rollback", Inputs: []string{"action_id"}, Outputs: []string{"status"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "block_ip":
		return a.blockIP(ctx, input)
	case "quarantine_file":
		return a.quarantineFile(ctx, input)
	case "kill_process":
		return a.killProcess(ctx, input)
	case "restart_service":
		return a.restartService(ctx, input)
	case "run_script":
		return a.runScript(ctx, input)
	case "rollback":
		return a.rollbackAction(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) blockIP(ctx context.Context, input agent.Input) (agent.Output, error) {
	ipStr, _ := input["ip"].(string)
	addr, err := ValidateIP(ipStr)
	if err != nil {
		return agent.Output{"error": err.Error()}, nil
	}

	argv, inverse := BlockIPArgv(addr)
	output, err := RunArgv(ctx, argv)
	status := "executed"
	if err != nil {
		status = fmt.Sprintf("failed: %v", err)
	}

	cmdStored := EncodeArgv(argv, inverse)
	rollbackStored := EncodeArgv(inverse, argv)
	rec := a.recordAction("block_ip", addr.String(), status, cmdStored, output, rollbackStored)

	return agent.Output{
		"status":           status,
		"ip":               addr.String(),
		"command":          cmdStored,
		"output":           output,
		"rollback_command": rollbackStored,
		"action_id":        rec.ID,
	}, nil
}

func (a *Agent) quarantineFile(ctx context.Context, input agent.Input) (agent.Output, error) {
	path, _ := input["path"].(string)
	if err := ValidateFilePath(path); err != nil {
		return agent.Output{"error": err.Error()}, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return agent.Output{"error": fmt.Sprintf("file not accessible: %v", err)}, nil
	}
	if err := CheckSymlinkOrDevice(path); err != nil {
		return agent.Output{"error": err.Error()}, nil
	}

	dest, err := ResolveQuarantineDest(a.quarantineDir, path)
	if err != nil {
		return agent.Output{"error": err.Error()}, nil
	}

	argv, inverse := MoveArgv(path, dest)
	output, runErr := RunArgv(ctx, argv)
	status := "executed"
	if runErr != nil {
		status = fmt.Sprintf("failed: %v", runErr)
	} else {
		os.Chmod(dest, 0400)
		_ = info
	}

	cmdStored := EncodeArgv(argv, inverse)
	rollbackStored := EncodeArgv(inverse, argv)
	rec := a.recordAction("quarantine_file", path, status, cmdStored, output, rollbackStored)

	return agent.Output{
		"status":           status,
		"original_path":    path,
		"quarantine_path":  dest,
		"command":          cmdStored,
		"rollback_command": rollbackStored,
		"action_id":        rec.ID,
	}, nil
}

func (a *Agent) killProcess(ctx context.Context, input agent.Input) (agent.Output, error) {
	name, _ := input["name"].(string)
	pidStr, _ := input["pid"].(string)

	if name == "" && pidStr == "" {
		return agent.Output{"error": "name or pid is required"}, nil
	}

	var argv []string
	target := name
	if pidStr != "" {
		pid, err := ValidatePIDString(pidStr)
		if err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		target = pidStr
		if isWindows() {
			argv = TaskkillPIDArgv(pid)
		} else {
			argv = KillPIDArgv(pid)
		}
	} else {
		if err := ValidateProcessName(name); err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		if isWindows() {
			argv = TaskkillNameArgv(name)
		} else {
			argv = PkillArgv(name)
		}
	}

	output, err := RunArgv(ctx, argv)
	status := "executed"
	if err != nil {
		status = fmt.Sprintf("failed: %v", err)
	}

	cmdStored := EncodeArgv(argv, nil)
	const noRollback = "N/A (process cannot be unkilled)"
	rec := a.recordAction("kill_process", target, status, cmdStored, output, noRollback)

	return agent.Output{
		"status":           status,
		"target":           target,
		"command":          cmdStored,
		"output":           output,
		"rollback_command": noRollback,
		"action_id":        rec.ID,
	}, nil
}

func (a *Agent) restartService(ctx context.Context, input agent.Input) (agent.Output, error) {
	name, _ := input["name"].(string)
	if err := ValidateServiceName(name); err != nil {
		return agent.Output{"error": err.Error()}, nil
	}

	// Ordered argv steps; each runs with no shell.
	var steps [][]string
	switch {
	case isWindows():
		steps = [][]string{ScStopArgv(name), ScStartArgv(name)}
	case isDarwin():
		steps = [][]string{LaunchctlRestartArgv(name)}
	default:
		steps = [][]string{SystemctlRestartArgv(name)}
	}

	var output string
	status := "executed"
	for _, argv := range steps {
		out, err := RunArgv(ctx, argv)
		output += out
		if err != nil {
			status = fmt.Sprintf("failed: %v", err)
			break
		}
	}

	// Rollback of a restart is another restart of the same service.
	rollbackArgv := steps[len(steps)-1]
	cmdStored := EncodeArgv(steps[0], rollbackArgv)
	rollbackStored := EncodeArgv(rollbackArgv, rollbackArgv)
	rec := a.recordAction("restart_service", name, status, cmdStored, output, rollbackStored)

	return agent.Output{
		"status":           status,
		"service":          name,
		"command":          cmdStored,
		"output":           output,
		"rollback_command": rollbackStored,
		"action_id":        rec.ID,
	}, nil
}

func (a *Agent) runScript(_ context.Context, input agent.Input) (agent.Output, error) {
	// Deny-by-default: flag + signed policy + per-execution approval token.
	// Deny-closed: CheckRunScriptGate refuses when any piece is absent, and
	// this server stack never spawns a shell for script bodies.
	if err := CheckRunScriptGate(input); err != nil {
		return agent.Output{"error": err.Error()}, nil
	}
	return agent.Output{"error": "run_script enabled but no script runner configured: refusing to execute script body"}, nil
}

func (a *Agent) rollbackAction(ctx context.Context, input agent.Input) (agent.Output, error) {
	actionID, _ := input["action_id"].(string)
	if actionID == "" {
		return agent.Output{"error": "action_id is required"}, nil
	}

	var rec ActionRecord
	err := a.db.QueryRowContext(ctx,
		`SELECT id, investigation_id, action_name, target, status, command, output, rollback_command, created_at
		 FROM response_actions WHERE id = ?`, actionID).
		Scan(&rec.ID, &rec.InvestigationID, &rec.Action, &rec.Target, &rec.Status, &rec.Command, &rec.Output, &rec.RollbackCmd, &rec.CreatedAt)
	if err != nil {
		return agent.Output{"error": fmt.Sprintf("action not found: %v", err)}, nil
	}

	if rec.RollbackCmd == "" || rec.RollbackCmd == "N/A" || isNoRollbackSentinel(rec.RollbackCmd) {
		return agent.Output{"status": "skipped", "message": "action cannot be rolled back"}, nil
	}
	if IsLegacyRollback(rec.RollbackCmd) {
		a.db.ExecContext(ctx,
			`UPDATE response_actions SET rollback_status = ? WHERE id = ?`, "legacy_unexecutable", actionID)
		log.Printf("response: rollback refused (legacy string row): id=%s action=%s", actionID, rec.Action)
		return agent.Output{"status": "legacy_unexecutable", "message": "stored string command predates argv-only mode and will not run", "action_id": actionID}, nil
	}
	stored, ok := DecodeStored(rec.RollbackCmd)
	if !ok {
		return agent.Output{"status": "skipped", "message": "action cannot be rolled back"}, nil
	}

	output, err := RunArgv(ctx, stored.Argv)
	status := "rolled_back"
	if err != nil {
		status = fmt.Sprintf("rollback_failed: %v", err)
	}

	a.db.ExecContext(ctx,
		`UPDATE response_actions SET rollback_status = ? WHERE id = ?`, status, actionID)

	return agent.Output{
		"status":           status,
		"action_id":        actionID,
		"rollback_command": rec.RollbackCmd,
		"output":           output,
	}, nil
}

func isNoRollbackSentinel(s string) bool {
	return len(s) >= 3 && s[:3] == "N/A"
}

func (a *Agent) recordAction(action, target, status, command, output, rollbackCmd string) *ActionRecord {
	rec := &ActionRecord{
		ID:          uuid.New().String(),
		Action:      action,
		Target:      target,
		Status:      status,
		Command:     command,
		Output:      output,
		RollbackCmd: rollbackCmd,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	data, _ := json.Marshal(rec)
	a.db.Exec(
		`INSERT INTO response_actions (id, investigation_id, action_name, target, status, command, output, rollback_command, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, "", rec.Action, rec.Target, rec.Status, rec.Command, rec.Output, rec.RollbackCmd, rec.CreatedAt)

	_ = data
	return rec
}
// TestDB exposes the handle for hermetic tests (seeding legacy rows).
func (a *Agent) TestDB() *sql.DB { return a.db }
