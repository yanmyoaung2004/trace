package response

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/transport"
)

type Executor struct {
	eventCh       chan<- *monitor.Event
	quarantineDir string
}

func NewExecutor(eventCh chan<- *monitor.Event) *Executor {
	qDir := filepath.Join(os.TempDir(), "trace-quarantine")
	os.MkdirAll(qDir, 0700)
	return &Executor{eventCh: eventCh, quarantineDir: qDir}
}

func (e *Executor) Execute(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	log.Printf("[executor] action: %s type=%s target=%s", action.ID, action.Type, action.Target)

	timeout := 30 * time.Second
	if action.Timeout > 0 {
		timeout = time.Duration(action.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Snapshot registry before modification
	if action.Type == "block_ip" || action.Type == "quarantine_file" {
		e.snapshotBefore(action)
	}

	result, err := e.executeSingle(ctx, action)
	if err != nil {
		return nil, err
	}

	// Execute chained actions
	if chain, ok := action.Params["chain"].([]any); ok && len(chain) > 0 {
		chainResults := make([]map[string]any, 0)
		for _, link := range chain {
			if linkStr, ok := link.(string); ok && linkStr != "" {
				chainAction := &transport.PendingAction{
					ID:   action.ID + "_chain_" + linkStr,
					Type: linkStr,
					Params: action.Params,
				}
				chainResult, chainErr := e.executeSingle(ctx, chainAction)
				if chainErr != nil {
					result["chain_aborted"] = true
					result["chain_error"] = chainErr.Error()
					break
				}
				chainResults = append(chainResults, chainResult)
			}
		}
		if len(chainResults) > 0 {
			result["chain_results"] = chainResults
		}
	}

	return result, nil
}

func (e *Executor) snapshotBefore(action *transport.PendingAction) {
	if action.Type != "block_ip" {
		return
	}
	ip, _ := action.Params["ip"].(string)
	if ip == "" {
		return
	}
	out, _ := e.runShell(context.Background(), getRegistryBackupCmd(ip))
	if out != "" {
		log.Printf("[executor] registry backup: %s", out[:min(len(out), 200)])
	}
}

func (e *Executor) executeSingle(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	switch action.Type {
	case "kill_process":
		return e.killProcess(ctx, action)
	case "quarantine_file":
		return e.quarantineFile(ctx, action)
	case "block_ip":
		return e.blockIP(ctx, action)
	case "run_script":
		return e.runScript(ctx, action)
	case "isolate_host":
		return e.isolateHost(ctx, action)
	case "release_host":
		return e.releaseHost(ctx, action)
	case "collect_forensics":
		return e.collectForensics(ctx, action)
	case "system_snapshot":
		return e.systemSnapshot(ctx)
	default:
		return nil, fmt.Errorf("unknown action type: %s", action.Type)
	}
}

func (e *Executor) killProcess(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	pid := 0
	if p, ok := action.Params["pid"].(float64); ok {
		pid = int(p)
	}
	name, _ := action.Params["name"].(string)

	if pid == 0 && name == "" {
		return nil, fmt.Errorf("pid or name required")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		if pid > 0 {
			cmd = exec.CommandContext(ctx, "taskkill", "/F", "/PID", fmt.Sprintf("%d", pid))
		} else {
			cmd = exec.CommandContext(ctx, "taskkill", "/F", "/IM", name)
		}
	case "linux", "darwin":
		if pid > 0 {
			cmd = exec.CommandContext(ctx, "kill", "-9", fmt.Sprintf("%d", pid))
		} else {
			cmd = exec.CommandContext(ctx, "pkill", "-9", name)
		}
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	outStr := string(output)
	if err != nil {
		return map[string]any{
			"status": "failed",
			"error":  fmt.Sprintf("%v: %s", err, outStr),
			"pid":    pid,
			"name":   name,
		}, nil
	}

	return map[string]any{
		"status": "killed",
		"output": outStr,
		"pid":    pid,
		"name":   name,
	}, nil
}

func (e *Executor) quarantineFile(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	path, _ := action.Params["path"].(string)
	if path == "" {
		path = action.Target
	}
	if path == "" {
		return nil, fmt.Errorf("path required")
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return map[string]any{"status": "not_found", "path": path}, nil
	}

	dest := filepath.Join(e.quarantineDir, filepath.Base(path)+".quarantined")

	var cmdStr, rollbackCmd string
	switch runtime.GOOS {
	case "windows":
		cmdStr = fmt.Sprintf("move /Y \"%s\" \"%s\"", path, dest)
		rollbackCmd = fmt.Sprintf("move /Y \"%s\" \"%s\"", dest, path)
	default:
		cmdStr = fmt.Sprintf("mv \"%s\" \"%s\"", path, dest)
		rollbackCmd = fmt.Sprintf("mv \"%s\" \"%s\"", dest, path)
	}

	output, err := e.runShell(ctx, cmdStr)
	if err != nil {
		return map[string]any{
			"status": "failed",
			"error":  fmt.Sprintf("%v", err),
			"path":   path,
		}, nil
	}

	os.Chmod(dest, 0400)

	return map[string]any{
		"status":           "quarantined",
		"original_path":    path,
		"quarantine_path":  dest,
		"rollback_command": rollbackCmd,
		"output":           output,
		"size":             info.Size(),
	}, nil
}

func (e *Executor) blockIP(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	ip, _ := action.Params["ip"].(string)
	if ip == "" {
		ip = action.Target
	}
	if ip == "" {
		return nil, fmt.Errorf("ip required")
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
		cmdStr = fmt.Sprintf("echo 'block in from %s to any' | pfctl -ef -", ip)
		rollbackCmd = fmt.Sprintf("pfctl -F rules")
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := e.runShell(ctx, cmdStr)
	status := "blocked"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
		if output != "" {
			if strings.Contains(output, "elevation") || strings.Contains(output, "Administrator") {
				errMsg = "requires administrator privileges — run agent as admin"
			} else {
				errMsg = output
			}
		}
	}

	return map[string]any{
		"status":           status,
		"ip":               ip,
		"command":          cmdStr,
		"output":           output,
		"rollback_command": rollbackCmd,
		"error":            errMsg,
	}, nil
}

func (e *Executor) runScript(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	script, _ := action.Params["script"].(string)
	if script == "" {
		return nil, fmt.Errorf("script content required")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "powershell", "-Command", script)
	case "linux", "darwin":
		cmd = exec.CommandContext(ctx, "sh", "-c", script)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
	outStr := string(output)
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}

	return map[string]any{
		"status": status,
		"output": outStr,
		"error":  errMsg,
	}, nil
}

func (e *Executor) isolateHost(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	var cmds []string
	switch runtime.GOOS {
	case "windows":
		cmds = []string{
			"netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound",
			"netsh advfirewall firewall add rule name=trace-isolate-allow dir=out action=allow remoteip=" + getServerIP(action),
		}
	case "linux":
		cmds = []string{
			"iptables -P INPUT DROP",
			"iptables -P OUTPUT DROP",
			"iptables -P FORWARD DROP",
			fmt.Sprintf("iptables -A OUTPUT -d %s -j ACCEPT", getServerIP(action)),
		}
	case "darwin":
		cmds = []string{
			"pfctl -e",
			fmt.Sprintf("echo 'block all\\npass out to %s' | pfctl -ef -", getServerIP(action)),
		}
	}

	results := make([]map[string]any, 0)
	for _, cmdStr := range cmds {
		output, err := e.runShell(ctx, cmdStr)
		r := map[string]any{"command": cmdStr, "output": output}
		if err != nil {
			r["status"] = "failed"
			r["error"] = err.Error()
		} else {
			r["status"] = "executed"
		}
		results = append(results, r)
	}

	return map[string]any{
		"status":  "isolated",
		"results": results,
	}, nil
}

func (e *Executor) releaseHost(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	var cmds []string
	switch runtime.GOOS {
	case "windows":
		cmds = []string{"netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound"}
	case "linux":
		cmds = []string{
			"iptables -P INPUT ACCEPT",
			"iptables -P OUTPUT ACCEPT",
			"iptables -P FORWARD ACCEPT",
			"iptables -F",
		}
	case "darwin":
		cmds = []string{"pfctl -F all", "pfctl -d"}
	}

	for _, cmdStr := range cmds {
		e.runShell(ctx, cmdStr)
	}

	return map[string]any{"status": "released"}, nil
}

func (e *Executor) collectForensics(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	forensics := map[string]any{}

	ps, _ := e.runShell(ctx, getProcessListCmd())
	forensics["process_list"] = ps

	net, _ := e.runShell(ctx, getNetstatCmd())
	forensics["network_connections"] = net

	df, _ := e.runShell(ctx, getDiskUsageCmd())
	forensics["disk_usage"] = df

	mem, _ := e.runShell(ctx, getMemoryCmd())
	forensics["memory_info"] = mem

	if runtime.GOOS == "windows" {
		recent, _ := e.runShell(ctx, "wevtutil qe System /c:50 /f:text /q:\"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]\"")
		forensics["recent_events"] = recent
	}

	return map[string]any{
		"status":    "collected",
		"forensics": forensics,
	}, nil
}

func (e *Executor) systemSnapshot(ctx context.Context) (map[string]any, error) {
	evt := &monitor.Event{
		Timestamp: time.Now().UTC(),
		Type:      monitor.EventSystemSnapshot,
		Severity:  monitor.SeverityInfo,
	}

	select {
	case e.eventCh <- evt:
	default:
	}

	return map[string]any{
		"status":   "snapshot_taken",
		"platform": runtime.GOOS,
		"uptime":   getUptime(),
	}, nil
}

func (e *Executor) runShell(ctx context.Context, cmdStr string) (string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "powershell", "-Command", cmdStr)
	default:
		cmd = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	data, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(data)), err
}

func getServerIP(action *transport.PendingAction) string {
	if ip, ok := action.Params["server_ip"].(string); ok && ip != "" {
		return ip
	}
	return "127.0.0.1"
}

func getProcessListCmd() string {
	switch runtime.GOOS {
	case "windows":
		return "Get-Process | Select-Object Id, ProcessName, CPU, @{N='MB';E={[math]::Round($_.WorkingSet64/1MB)}} | ConvertTo-Json -Compress"
	case "linux":
		return "ps aux --sort=-%cpu | head -50"
	default:
		return "ps aux -r | head -50"
	}
}

func getNetstatCmd() string {
	switch runtime.GOOS {
	case "windows":
		return "netstat -ano | Select-String TCP,UDP"
	case "linux":
		return "ss -tunap | head -50"
	default:
		return "lsof -i -P -n | head -50"
	}
}

func getDiskUsageCmd() string {
	switch runtime.GOOS {
	case "windows":
		return "Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free | ConvertTo-Json -Compress"
	default:
		return "df -h / | tail -1"
	}
}

func getMemoryCmd() string {
	switch runtime.GOOS {
	case "windows":
		return "Get-CimInstance Win32_OperatingSystem | Select-Object @{N='Total';E={[math]::Round($_.TotalVisibleMemorySize/1MB)}},@{N='Free';E={[math]::Round($_.FreePhysicalMemory/1MB)}} | ConvertTo-Json -Compress"
	case "linux":
		return "free -h"
	default:
		return "vm_stat"
	}
}

func getRegistryBackupCmd(ip string) string {
	switch runtime.GOOS {
	case "windows":
		ruleName := "trace-block-" + strings.ReplaceAll(ip, ".", "-")
		return fmt.Sprintf("reg export HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy %s_fw_backup.reg", ruleName)
	default:
		return "true"
	}
}

func getUptime() string {
	switch runtime.GOOS {
	case "windows":
		out, _ := exec.Command("powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime").Output()
		return strings.TrimSpace(string(out))
	case "linux":
		data, _ := os.ReadFile("/proc/uptime")
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			return parts[0] + "s"
		}
		return "unknown"
	default:
		out, _ := exec.Command("uptime").Output()
		return strings.TrimSpace(string(out))
	}
}
