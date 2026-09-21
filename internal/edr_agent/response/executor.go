package response

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/transport"
	shared "github.com/yanmyoaung2004/trace/internal/response"
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

	// Client-side chains are rejected: the server must expand chains into
	// individually authorized actions.
	if err := shared.CheckChainRejected(action.Params); err != nil {
		return nil, err
	}

	timeout := 30 * time.Second
	if action.Timeout > 0 {
		timeout = time.Duration(action.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return e.executeSingle(ctx, action)
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

// paramPID accepts float64 (JSON), int, or digits-only string.
func paramPID(params map[string]any) (int, bool, error) {
	v, ok := params["pid"]
	if !ok || v == nil {
		return 0, false, nil
	}
	switch n := v.(type) {
	case float64:
		if n != float64(int(n)) || n <= 0 {
			return 0, true, fmt.Errorf("invalid pid %v", v)
		}
		if err := shared.ValidatePID(int(n)); err != nil {
			return 0, true, err
		}
		return int(n), true, nil
	case int:
		if err := shared.ValidatePID(n); err != nil {
			return 0, true, err
		}
		return n, true, nil
	case string:
		pid, err := shared.ValidatePIDString(n)
		if err != nil {
			return 0, true, err
		}
		return pid, true, nil
	default:
		return 0, true, fmt.Errorf("invalid pid %v", v)
	}
}

func (e *Executor) killProcess(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	pid, hasPID, err := paramPID(action.Params)
	if err != nil {
		return nil, err
	}
	name, _ := action.Params["name"].(string)

	if !hasPID && name == "" {
		return nil, fmt.Errorf("pid or name required")
	}

	var argv []string
	if hasPID {
		if runtime.GOOS == "windows" {
			argv = shared.TaskkillPIDArgv(pid)
		} else {
			argv = shared.KillPIDArgv(pid)
		}
	} else {
		if err := shared.ValidateProcessName(name); err != nil {
			return nil, err
		}
		if runtime.GOOS == "windows" {
			argv = shared.TaskkillNameArgv(name)
		} else {
			argv = shared.PkillArgv(name)
		}
	}

	output, err := shared.RunArgv(ctx, argv)
	if err != nil {
		return map[string]any{
			"status": "failed",
			"error":  fmt.Sprintf("%v: %s", err, output),
			"pid":    pid,
			"name":   name,
		}, nil
	}

	return map[string]any{
		"status": "killed",
		"output": output,
		"pid":    pid,
		"name":   name,
	}, nil
}

func (e *Executor) quarantineFile(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	path, _ := action.Params["path"].(string)
	if path == "" {
		path = action.Target
	}
	if err := shared.ValidateFilePath(path); err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return map[string]any{"status": "not_found", "path": path}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := shared.CheckSymlinkOrDevice(path); err != nil {
		return nil, err
	}

	os.MkdirAll(e.quarantineDir, 0700)
	dest, err := shared.ResolveQuarantineDest(e.quarantineDir, path)
	if err != nil {
		return nil, err
	}

	argv, inverse := shared.MoveArgv(path, dest)
	output, err := shared.RunArgv(ctx, argv)
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
		"rollback_command": shared.EncodeArgv(inverse, argv),
		"output":           output,
		"size":             info.Size(),
	}, nil
}

func (e *Executor) blockIP(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	ipStr, _ := action.Params["ip"].(string)
	if ipStr == "" {
		ipStr = action.Target
	}
	addr, err := shared.ValidateIP(ipStr)
	if err != nil {
		return nil, err
	}

	argv, inverse := shared.BlockIPArgv(addr)
	output, err := shared.RunArgv(ctx, argv)
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
		"ip":               addr.String(),
		"command":          shared.EncodeArgv(argv, inverse),
		"output":           output,
		"rollback_command": shared.EncodeArgv(inverse, argv),
		"error":            errMsg,
	}, nil
}

func (e *Executor) runScript(_ context.Context, action *transport.PendingAction) (map[string]any, error) {
	// Deny-by-default: flag + signed policy + per-execution approval token.
	// Deny-closed: any absence is an error, and the script body is never run.
	if err := shared.CheckRunScriptGate(action.Params); err != nil {
		return nil, err
	}
	// Even when gated open, scripts execute only via provider-side RunScript
	// in this build; the on-host executor refuses raw bodies so no shell
	// string is ever spawned here.
	script, _ := action.Params["script"].(string)
	if script == "" {
		return nil, fmt.Errorf("script content required")
	}
	return nil, fmt.Errorf("run_script enabled but no script runner configured: refusing to execute script body on host")
}

func (e *Executor) isolateHost(ctx context.Context, action *transport.PendingAction) (map[string]any, error) {
	serverIP, err := validatedServerIP(action)
	if err != nil {
		return nil, err
	}

	// Ordered argv steps, no shell. Each step runs independently.
	var steps [][]string
	switch runtime.GOOS {
	case "windows":
		name := "trace-isolate-allow"
		steps = [][]string{
			{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
			{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + name, "dir=out", "action=allow", "remoteip=" + serverIP},
		}
	case "linux":
		steps = [][]string{
			{"iptables", "-P", "INPUT", "DROP"},
			{"iptables", "-P", "OUTPUT", "DROP"},
			{"iptables", "-P", "FORWARD", "DROP"},
			{"iptables", "-A", "OUTPUT", "-d", serverIP, "-j", "ACCEPT"},
		}
	case "darwin":
		// pf rules go through a temp file loaded by argv; never a shell pipe.
		tmp, err := os.CreateTemp("", "trace-isolate-*.pf.conf")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString("block all\npass out to " + serverIP + "\n"); err != nil {
			tmp.Close()
			return nil, err
		}
		tmp.Close()
		steps = [][]string{
			{"pfctl", "-e"},
			{"pfctl", "-f", tmp.Name()},
		}
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	results := make([]map[string]any, 0, len(steps))
	for _, argv := range steps {
		output, err := shared.RunArgv(ctx, argv)
		r := map[string]any{"command": argv, "output": output}
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

func (e *Executor) releaseHost(ctx context.Context, _ *transport.PendingAction) (map[string]any, error) {
	var steps [][]string
	switch runtime.GOOS {
	case "windows":
		steps = [][]string{
			{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "allowinbound,allowoutbound"},
		}
	case "linux":
		steps = [][]string{
			{"iptables", "-P", "INPUT", "ACCEPT"},
			{"iptables", "-P", "OUTPUT", "ACCEPT"},
			{"iptables", "-P", "FORWARD", "ACCEPT"},
			{"iptables", "-F"},
		}
	case "darwin":
		steps = [][]string{{"pfctl", "-F", "all"}, {"pfctl", "-d"}}
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	for _, argv := range steps {
		shared.RunArgv(ctx, argv)
	}

	return map[string]any{"status": "released"}, nil
}

// runFixed runs a fixed argv (no variable input) and returns at most the
// first 50 lines, truncated. Errors are swallowed by the caller.
func runFixed(ctx context.Context, argv []string) string {
	out, _ := shared.RunArgv(ctx, argv)
	lines := strings.Split(out, "\n")
	if len(lines) > 50 {
		lines = lines[:50]
	}
	return strings.Join(lines, "\n")
}

func (e *Executor) collectForensics(ctx context.Context, _ *transport.PendingAction) (map[string]any, error) {
	forensics := map[string]any{}
	switch runtime.GOOS {
	case "windows":
		forensics["process_list"] = runFixed(ctx, []string{"tasklist"})
		forensics["network_connections"] = runFixed(ctx, []string{"netstat", "-ano"})
		forensics["disk_usage"] = runFixed(ctx, []string{"wmic", "logicaldisk", "get", "name,freespace,size"})
		forensics["memory_info"] = runFixed(ctx, []string{"wmic", "os", "get", "freephysicalmemory,totalvisiblememorysize"})
		forensics["recent_events"] = runFixed(ctx, []string{"wevtutil", "qe", "System", "/c:50", "/f:text", "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"})
	case "linux":
		forensics["process_list"] = runFixed(ctx, []string{"ps", "aux"})
		forensics["network_connections"] = runFixed(ctx, []string{"ss", "-tunap"})
		forensics["disk_usage"] = runFixed(ctx, []string{"df", "-h", "/"})
		forensics["memory_info"] = runFixed(ctx, []string{"free", "-h"})
	default:
		forensics["process_list"] = runFixed(ctx, []string{"ps", "aux"})
		forensics["network_connections"] = runFixed(ctx, []string{"lsof", "-i", "-P", "-n"})
		forensics["disk_usage"] = runFixed(ctx, []string{"df", "-h", "/"})
		forensics["memory_info"] = runFixed(ctx, []string{"vm_stat"})
	}

	return map[string]any{
		"status":    "collected",
		"forensics": forensics,
	}, nil
}

func (e *Executor) systemSnapshot(ctx context.Context) (map[string]any, error) {
	_ = ctx
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

// deniedShell is the single gated legacy-string helper for this package. It
// always denies and never spawns a process: argv-only mode has no string
// runner. It exists so a grep for a string runner lands here and stops.
func deniedShell(_ context.Context, cmdStr string) (string, error) {
	_ = cmdStr
	return "", fmt.Errorf("legacy string execution disabled: argv-only mode")
}

func validatedServerIP(action *transport.PendingAction) (string, error) {
	ipStr, _ := action.Params["server_ip"].(string)
	if ipStr == "" {
		return "127.0.0.1", nil
	}
	addr, err := shared.ValidateIP(ipStr)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func getUptime() string {
	switch runtime.GOOS {
	case "windows":
		out, _ := shared.RunArgv(context.Background(), []string{"net", "statistics", "workstation"})
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(strings.ToLower(line), "since") {
				return strings.TrimSpace(line)
			}
		}
		return "unknown"
	case "linux":
		data, _ := os.ReadFile("/proc/uptime")
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			return parts[0] + "s"
		}
		return "unknown"
	default:
		out, _ := shared.RunArgv(context.Background(), []string{"uptime"})
		if out == "" {
			return "unknown"
		}
		return out
	}
}
