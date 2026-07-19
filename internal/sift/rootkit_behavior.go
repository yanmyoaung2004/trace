package sift

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type BehaviorCheck struct {
	Name        string
	Description string
	Severity    int
	Check       func(ctx context.Context) (bool, string, error)
}

func BehaviorChecks() []BehaviorCheck {
	return []BehaviorCheck{
		{
			Name:        "hidden-process",
			Description: "Check for processes hidden from /proc vs ps",
			Severity:    5,
			Check:       checkHiddenProcesses,
		},
		{
			Name:        "suspicious-kernel-module",
			Description: "Check for known malicious kernel modules",
			Severity:    5,
			Check:       checkSuspiciousModules,
		},
		{
			Name:        "process-hijacking",
			Description: "Check for LD_PRELOAD or injected processes",
			Severity:    4,
			Check:       checkProcessHijacking,
		},
		{
			Name:        "suspicious-memory",
			Description: "Check for known malware memory regions",
			Severity:    4,
			Check:       checkSuspiciousMemory,
		},
		{
			Name:        "fileless-malware",
			Description: "Check for fileless malware indicators (memfd, anonymous mappings)",
			Severity:    5,
			Check:       checkFilelessMalware,
		},
		{
			Name:        "persistence-mechanisms",
			Description: "Check for suspicious cron jobs, systemd services, startup items",
			Severity:    3,
			Check:       checkPersistence,
		},
		{
			Name:        "container-escape",
			Description: "Check for container escape indicators",
			Severity:    5,
			Check:       checkContainerEscape,
		},
		{
			Name:        "common-malware-ports",
			Description: "Check for listening ports commonly used by malware",
			Severity:    3,
			Check:       checkMalwarePorts,
		},
	}
}

func RunBehaviorChecks(ctx context.Context) []map[string]any {
	var results []map[string]any

	for _, bc := range BehaviorChecks() {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		found, detail, err := bc.Check(checkCtx)
		cancel()

		res := map[string]any{
			"check":       bc.Name,
			"description": bc.Description,
			"severity":    bc.Severity,
		}
		if err != nil {
			res["error"] = err.Error()
			res["status"] = "error"
		} else if found {
			res["status"] = "suspicious"
			res["detail"] = detail
		} else {
			res["status"] = "clean"
		}
		results = append(results, res)
	}

	return results
}

func checkHiddenProcesses(ctx context.Context) (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}

	psOutput, err := exec.CommandContext(ctx, "ps", "aux").Output()
	if err != nil {
		return false, "", err
	}

	psLines := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(psOutput)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 11 {
			psLines[fields[1]] = true
		}
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return false, "", nil
	}
	defer procDir.Close()

	entries, _ := procDir.Readdir(-1)
	var hidden []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if !isNumeric(pid) {
			continue
		}
		if !psLines[pid] {
			comm, _ := os.ReadFile(filepath.Join("/proc", pid, "comm"))
			name := strings.TrimSpace(string(comm))
			if name != "" {
				hidden = append(hidden, fmt.Sprintf("PID %s (%s)", pid, name))
			}
		}
	}

	if len(hidden) > 0 {
		return true, fmt.Sprintf("Hidden processes: %s", strings.Join(hidden, ", ")), nil
	}
	return false, "", nil
}

func checkSuspiciousModules(ctx context.Context) (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}

	data, err := exec.CommandContext(ctx, "lsmod").Output()
	if err != nil {
		return false, "", nil
	}

	suspicious := []string{"rootkit", "sneaky", "hideproc", "kdmapper"}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, s := range suspicious {
			if strings.Contains(lower, s) {
				return true, fmt.Sprintf("Suspicious kernel module: %s", strings.Fields(line)[0]), nil
			}
		}
	}

	return false, "", nil
}

func checkProcessHijacking(ctx context.Context) (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}

	data, err := exec.CommandContext(ctx, "cat", "/proc/self/environ").Output()
	if err != nil {
		return false, "", nil
	}

	if strings.Contains(string(data), "LD_PRELOAD=") {
		for _, part := range strings.Split(string(data), "\x00") {
			if strings.HasPrefix(part, "LD_PRELOAD=") {
				return true, fmt.Sprintf("LD_PRELOAD detected: %s", strings.TrimPrefix(part, "LD_PRELOAD=")), nil
			}
		}
	}

	return false, "", nil
}

func checkSuspiciousMemory(ctx context.Context) (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return false, "", nil
	}
	defer procDir.Close()

	entries, _ := procDir.Readdir(-1)
	for _, e := range entries {
		if !e.IsDir() || !isNumeric(e.Name()) {
			continue
		}

		maps, err := os.ReadFile(filepath.Join("/proc", e.Name(), "maps"))
		if err != nil {
			continue
		}

		mapsStr := string(maps)
		if strings.Contains(mapsStr, "[vdso]") && strings.Contains(mapsStr, "rwx") {
			return true, fmt.Sprintf("PID %s has suspicious W+X memory mappings", e.Name()), nil
		}

		if strings.Count(mapsStr, "[heap]") > 2 {
			return true, fmt.Sprintf("PID %s has unusual heap mappings", e.Name()), nil
		}
	}

	return false, "", nil
}

func checkFilelessMalware(ctx context.Context) (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}

	data, err := exec.CommandContext(ctx, "cat", "/proc/self/maps").Output()
	if err != nil {
		return false, "", nil
	}

	mapsStr := string(data)
	if strings.Contains(mapsStr, "memfd:") || strings.Contains(mapsStr, "/memfd:") {
		re := regexp.MustCompile(`memfd:[^\s]+`)
		matches := re.FindAllString(mapsStr, -1)
		if len(matches) > 0 {
			return true, fmt.Sprintf("Fileless execution via memfd: %s", strings.Join(matches, ", ")), nil
		}
	}

	return false, "", nil
}

func checkPersistence(ctx context.Context) (bool, string, error) {
	if runtime.GOOS == "windows" {
		data, err := exec.CommandContext(ctx, "schtasks", "/query", "/fo", "csv", "/v").Output()
		if err == nil {
			suspicious := []string{"updater", "systemupdate", "securityscan", "windowsupdate"}
			lines := strings.Split(string(data), "\n")
			var found []string
			for _, line := range lines {
				l := strings.ToLower(line)
				for _, s := range suspicious {
					if strings.Contains(l, s) {
						found = append(found, extractTaskName(line))
						break
					}
				}
			}
			if len(found) > 0 {
				return true, fmt.Sprintf("Suspicious scheduled tasks: %s", strings.Join(found, ", ")), nil
			}
		}
		return false, "", nil
	}

	if runtime.GOOS == "linux" {
		crontab, err := exec.CommandContext(ctx, "crontab", "-l").Output()
		if err == nil {
			cronStr := string(crontab)
			suspicious := []string{"curl", "wget", "bash -c", "base64", "chmod +x"}
			for _, s := range suspicious {
				if strings.Contains(strings.ToLower(cronStr), s) {
					return true, fmt.Sprintf("Suspicious cron entry containing %q", s), nil
				}
			}
		}

		systemdDir := "/etc/systemd/system"
		if entries, err := os.ReadDir(systemdDir); err == nil {
			for _, e := range entries {
				name := strings.ToLower(e.Name())
				if (strings.Contains(name, "updater") || strings.Contains(name, "update")) && !strings.Contains(name, "unattended") {
					return true, fmt.Sprintf("Suspicious systemd service: %s", e.Name()), nil
				}
			}
		}

		return false, "", nil
	}

	return false, "", nil
}

func checkContainerEscape(ctx context.Context) (bool, string, error) {
	if runtime.GOOS != "linux" {
		return false, "", nil
	}

	sensitiveMounts := []string{"/var/run/docker.sock", "/proc/1/ns", "/host"}
	for _, m := range sensitiveMounts {
		if _, err := os.Stat(m); err == nil {
			return true, fmt.Sprintf("Container escape risk: %s is accessible", m), nil
		}
	}

	return false, "", nil
}

func checkMalwarePorts(ctx context.Context) (bool, string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "netstat", "-an")
	} else {
		cmd = exec.CommandContext(ctx, "ss", "-tlnp")
	}

	data, err := cmd.Output()
	if err != nil {
		cmd = exec.CommandContext(ctx, "netstat", "-tlnp")
		data, err = cmd.Output()
		if err != nil {
			return false, "", nil
		}
	}

	malwarePorts := map[string]string{
		"4444":  "Metasploit default",
		"5555":  "Android ADB / malware",
		"6666":  "IRC bot / malware C2",
		"6667":  "IRC bot / malware C2",
		"6668":  "IRC bot / malware C2",
		"6669":  "IRC bot / malware C2",
		"1337":  "Common backdoor port",
		"2332":  "GroupBusiness malware",
		"31337": "Back Orifice / Elite backdoor",
		"44344": "Cabinet malware",
	}

	lines := strings.Split(string(data), "\n")
	var found []string
	for _, line := range lines {
		for port, desc := range malwarePorts {
			if strings.Contains(line, fmt.Sprintf(":%s", port)) && (strings.Contains(line, "LISTEN") || strings.Contains(line, "LISTENING")) {
				found = append(found, fmt.Sprintf("port %s (%s)", port, desc))
				break
			}
		}
	}

	if len(found) > 0 {
		return true, fmt.Sprintf("Suspicious listening ports: %s", strings.Join(found, ", ")), nil
	}
	return false, "", nil
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func extractTaskName(line string) string {
	parts := strings.Split(line, ",")
	if len(parts) > 0 {
		return strings.Trim(parts[0], `" `)
	}
	return ""
}

func init() {
	_ = os.Hostname
	_ = fmt.Sprintf
	_ = regexp.Compile
}
