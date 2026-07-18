package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/agent"
)

type ActionRecord struct {
	ID              string    `json:"id"`
	InvestigationID string    `json:"investigation_id"`
	Action          string    `json:"action"`
	Target          string    `json:"target"`
	Status          string    `json:"status"`
	Command         string    `json:"command"`
	Output          string    `json:"output"`
	RollbackCmd     string    `json:"rollback_command"`
	RollbackStatus  string    `json:"rollback_status"`
	CreatedAt       string    `json:"created_at"`
}

type Agent struct {
	db        *sql.DB
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
	case "rollback":
		return a.rollbackAction(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) blockIP(_ context.Context, input agent.Input) (agent.Output, error) {
	ip, _ := input["ip"].(string)
	if ip == "" {
		return agent.Output{"error": "ip is required"}, nil
	}

	var cmdStr, rollbackCmd string
	switch runtime.GOOS {
	case "windows":
		ruleName := fmt.Sprintf("trace-block-%s", strings.ReplaceAll(ip, ".", "-"))
		cmdStr = fmt.Sprintf("netsh advfirewall firewall add rule name=%s dir=in action=block remoteip=%s", ruleName, ip)
		rollbackCmd = fmt.Sprintf("netsh advfirewall firewall delete rule name=%s", ruleName)
	case "linux":
		cmdStr = fmt.Sprintf("iptables -A INPUT -s %s -j DROP", ip)
		rollbackCmd = fmt.Sprintf("iptables -D INPUT -s %s -j DROP", ip)
	case "darwin":
		cmdStr = fmt.Sprintf("pfctl -t trace -T add %s", ip)
		rollbackCmd = fmt.Sprintf("pfctl -t trace -T delete %s", ip)
	default:
		return agent.Output{"error": fmt.Sprintf("unsupported OS: %s", runtime.GOOS)}, nil
	}

	output, err := a.runCommand(cmdStr)
	status := "executed"
	if err != nil {
		status = fmt.Sprintf("failed: %v", err)
	}

	rec := a.recordAction("block_ip", ip, status, cmdStr, output, rollbackCmd)

	return agent.Output{
		"status":          status,
		"ip":              ip,
		"command":         cmdStr,
		"output":          output,
		"rollback_command": rollbackCmd,
		"action_id":       rec.ID,
	}, nil
}

func (a *Agent) quarantineFile(_ context.Context, input agent.Input) (agent.Output, error) {
	path, _ := input["path"].(string)
	if path == "" {
		return agent.Output{"error": "path is required"}, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return agent.Output{"error": fmt.Sprintf("file not accessible: %v", err)}, nil
	}

	dest := filepath.Join(a.quarantineDir, filepath.Base(path)+"."+uuid.New().String()[:8])

	var cmdStr, rollbackCmd string
	switch runtime.GOOS {
	case "windows":
		cmdStr = fmt.Sprintf("move \"%s\" \"%s\"", path, dest)
		rollbackCmd = fmt.Sprintf("move \"%s\" \"%s\"", dest, path)
	default:
		cmdStr = fmt.Sprintf("mv \"%s\" \"%s\"", path, dest)
		rollbackCmd = fmt.Sprintf("mv \"%s\" \"%s\"", dest, path)
	}

	output, err := a.runCommand(cmdStr)
	status := "executed"
	if err != nil {
		status = fmt.Sprintf("failed: %v", err)
	} else {
		os.Chmod(dest, 0400)
		_ = info
	}

	rec := a.recordAction("quarantine_file", path, status, cmdStr, output, rollbackCmd)

	return agent.Output{
		"status":           status,
		"original_path":    path,
		"quarantine_path":  dest,
		"command":          cmdStr,
		"rollback_command": rollbackCmd,
		"action_id":        rec.ID,
	}, nil
}

func (a *Agent) killProcess(_ context.Context, input agent.Input) (agent.Output, error) {
	name, _ := input["name"].(string)
	pid, _ := input["pid"].(string)

	if name == "" && pid == "" {
		return agent.Output{"error": "name or pid is required"}, nil
	}

	var cmdStr, rollbackCmd string
	target := name
	if pid != "" {
		target = pid
	}

	switch runtime.GOOS {
	case "windows":
		if pid != "" {
			cmdStr = fmt.Sprintf("taskkill /F /PID %s", pid)
		} else {
			cmdStr = fmt.Sprintf("taskkill /F /IM %s", name)
		}
		rollbackCmd = "N/A (process cannot be unkilled)"
	case "linux", "darwin":
		if pid != "" {
			cmdStr = fmt.Sprintf("kill -9 %s", pid)
		} else {
			cmdStr = fmt.Sprintf("pkill -9 %s", name)
		}
		rollbackCmd = "N/A (process cannot be unkilled)"
	default:
		return agent.Output{"error": fmt.Sprintf("unsupported OS: %s", runtime.GOOS)}, nil
	}

	output, err := a.runCommand(cmdStr)
	status := "executed"
	if err != nil {
		status = fmt.Sprintf("failed: %v", err)
	}

	rec := a.recordAction("kill_process", target, status, cmdStr, output, rollbackCmd)

	return agent.Output{
		"status":          status,
		"target":          target,
		"command":         cmdStr,
		"output":          output,
		"rollback_command": rollbackCmd,
		"action_id":       rec.ID,
	}, nil
}

func (a *Agent) restartService(_ context.Context, input agent.Input) (agent.Output, error) {
	name, _ := input["name"].(string)
	if name == "" {
		return agent.Output{"error": "name is required"}, nil
	}

	var cmdStr, rollbackCmd string
	switch runtime.GOOS {
	case "windows":
		cmdStr = fmt.Sprintf("sc stop %s; sc start %s", name, name)
		rollbackCmd = fmt.Sprintf("sc stop %s; sc start %s", name, name)
	case "linux":
		cmdStr = fmt.Sprintf("systemctl restart %s", name)
		rollbackCmd = fmt.Sprintf("systemctl restart %s", name)
	case "darwin":
		cmdStr = fmt.Sprintf("launchctl kickstart -k system/%s", name)
		rollbackCmd = fmt.Sprintf("launchctl kickstart -k system/%s", name)
	default:
		return agent.Output{"error": fmt.Sprintf("unsupported OS: %s", runtime.GOOS)}, nil
	}

	output, err := a.runCommand(cmdStr)
	status := "executed"
	if err != nil {
		status = fmt.Sprintf("failed: %v", err)
	}

	rec := a.recordAction("restart_service", name, status, cmdStr, output, rollbackCmd)

	return agent.Output{
		"status":          status,
		"service":         name,
		"command":         cmdStr,
		"output":          output,
		"rollback_command": rollbackCmd,
		"action_id":       rec.ID,
	}, nil
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

	if rec.RollbackCmd == "" || rec.RollbackCmd == "N/A" {
		return agent.Output{"status": "skipped", "message": "action cannot be rolled back"}, nil
	}

	output, err := a.runCommand(rec.RollbackCmd)
	status := "rolled_back"
	if err != nil {
		status = fmt.Sprintf("rollback_failed: %v", err)
	}

	a.db.ExecContext(ctx,
		`UPDATE response_actions SET rollback_status = ? WHERE id = ?`, status, actionID)

	return agent.Output{
		"status":       status,
		"action_id":    actionID,
		"rollback_command": rec.RollbackCmd,
		"output":       output,
	}, nil
}

func (a *Agent) runCommand(cmd string) (string, error) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("powershell", "-Command", cmd)
	default:
		c = exec.Command("sh", "-c", cmd)
	}

	output, err := c.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err != nil {
		log.Printf("response: command failed: %s\noutput: %s\nerror: %v", cmd, outStr, err)
		return outStr, err
	}

	log.Printf("response: command succeeded: %s\noutput: %s", cmd, outStr)
	return outStr, nil
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
