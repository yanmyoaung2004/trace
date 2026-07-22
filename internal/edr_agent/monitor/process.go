package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	data, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

type ProcessMonitor struct {
	eventCh  chan<- *Event
	interval time.Duration
	done     chan struct{}
	prevPIDs map[int]struct{}
	mu       sync.Mutex
	enabled  bool
}

func NewProcessMonitor(eventCh chan<- *Event) *ProcessMonitor {
	return &ProcessMonitor{
		eventCh:  eventCh,
		interval: 10 * time.Second,
		done:     make(chan struct{}),
		prevPIDs: make(map[int]struct{}),
	}
}

func (pm *ProcessMonitor) Start(ctx context.Context) error {
	switch runtime.GOOS {
	case "windows":
		return pm.startWindows(ctx)
	case "linux":
		return pm.startLinux(ctx)
	case "darwin":
		return pm.startDarwin(ctx)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func (pm *ProcessMonitor) Stop() {
	close(pm.done)
}

func (pm *ProcessMonitor) startWindows(ctx context.Context) error {
	pm.enabled = true
	go pm.pollingLoop(ctx)
	return nil
}

func (pm *ProcessMonitor) startLinux(ctx context.Context) error {
	pm.enabled = true
	go pm.pollingLoop(ctx)
	return nil
}

func (pm *ProcessMonitor) startDarwin(ctx context.Context) error {
	pm.enabled = true
	go pm.pollingLoop(ctx)
	return nil
}

func (pm *ProcessMonitor) pollingLoop(ctx context.Context) {
	snapshotSent := false
	tick := time.NewTicker(pm.interval)
	defer tick.Stop()

	for {
		select {
		case <-pm.done:
			return
		case <-tick.C:
			current := pm.getProcessSnapshot()
			if !snapshotSent {
				pm.sendSnapshot(current)
				snapshotSent = true
			}
			pm.detectChanges(current)
		}
	}
}

type procEntry struct {
	PID     int
	PPID    int
	Name    string
	CmdLine string
}

func (pm *ProcessMonitor) getProcessSnapshot() map[int]*procEntry {
	entries := make(map[int]*procEntry)

	switch runtime.GOOS {
	case "windows":
		pm.readProcWindows(entries)
	case "linux":
		pm.readProcLinux(entries)
	case "darwin":
		pm.readProcDarwin(entries)
	}

	return entries
}

func (pm *ProcessMonitor) readProcLinux(entries map[int]*procEntry) {
	procDir, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, d := range procDir {
		if !d.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(d.Name(), "%d", &pid); err != nil {
			continue
		}

		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}

		fields := strings.Fields(string(stat))
		if len(fields) < 15 {
			continue
		}

		name := strings.Trim(fields[1], "()")
		ppid := 0
		fmt.Sscanf(fields[3], "%d", &ppid)

		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		cmdStr := strings.ReplaceAll(string(cmdline), "\x00", " ")

		entries[pid] = &procEntry{
			PID:     pid,
			PPID:    ppid,
			Name:    name,
			CmdLine: strings.TrimSpace(cmdStr),
		}
	}
}

func (pm *ProcessMonitor) readProcWindows(entries map[int]*procEntry) {
	// Use PowerShell as fallback; ETW subscription would be preferred
	data, err := runCmd("powershell", "-Command",
		"Get-Process | Select-Object Id, Name, @{N='P';E={$_.Parent.Id}}, CommandLine | ConvertTo-Json -Compress")
	if err != nil {
		return
	}

	type winProc struct {
		ID          int    `json:"Id"`
		Name        string `json:"Name"`
		P           int    `json:"P"`
		CommandLine string `json:"CommandLine"`
	}

	var procs []winProc
	if err := json.Unmarshal([]byte(data), &procs); err != nil {
		return
	}
	for _, p := range procs {
		entries[p.ID] = &procEntry{
			PID:     p.ID,
			PPID:    p.P,
			Name:    p.Name,
			CmdLine: p.CommandLine,
		}
	}
}

func (pm *ProcessMonitor) readProcDarwin(entries map[int]*procEntry) {
	data, err := runCmd("ps", "-eo", "pid,ppid,comm,args")
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		var pid, ppid int
		fmt.Sscanf(fields[0], "%d", &pid)
		fmt.Sscanf(fields[1], "%d", &ppid)
		entries[pid] = &procEntry{
			PID:     pid,
			PPID:    ppid,
			Name:    fields[2],
			CmdLine: strings.Join(fields[3:], " "),
		}
	}
}

func (pm *ProcessMonitor) detectChanges(current map[int]*procEntry) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// New processes
	for pid, entry := range current {
		if _, exists := pm.prevPIDs[pid]; !exists {
			pm.emitEvent(EventProcessCreate, entry)
		}
	}

	// Terminated processes
	for pid := range pm.prevPIDs {
		if _, exists := current[pid]; !exists {
			pm.emitEvent(EventProcessTerminate, &procEntry{PID: pid, Name: "unknown"})
		}
	}

	pm.prevPIDs = make(map[int]struct{})
	for pid := range current {
		pm.prevPIDs[pid] = struct{}{}
	}
}

func (pm *ProcessMonitor) emitEvent(etype EventType, entry *procEntry) {
	sev := SeverityInfo
	if isSuspiciousProcess(entry.Name) {
		sev = SeverityWarning
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Type:      etype,
		Severity:  sev,
		Process: &ProcessInfo{
			PID:     entry.PID,
			PPID:    entry.PPID,
			Name:    entry.Name,
			Path:    entry.CmdLine,
			CmdLine: entry.CmdLine,
		},
		Annotations: map[string]string{},
	}

	if sev >= SeverityWarning {
		evt.Annotations["reason"] = "suspicious_process"
	}

	select {
	case pm.eventCh <- evt:
	default:
	}
}

func (pm *ProcessMonitor) sendSnapshot(entries map[int]*procEntry) {
	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Type:      EventSystemSnapshot,
		Severity:  SeverityInfo,
		System: &SnapshotInfo{
			Processes: len(entries),
		},
	}
	select {
	case pm.eventCh <- evt:
	default:
	}
}

var suspiciousProcesses = []string{
	"mimikatz", "powershell", "cmd.exe", "wscript", "cscript", "mshta",
	"rundll32", "regsvr32", "certutil", "bitsadmin", "net.exe", "net1.exe",
	"taskkill", "wmic", "schtasks", "vssadmin", "bcdedit", "wevtutil",
	"pnputil", "sc.exe", "wget.exe", "curl", "nc.exe", "ncat",
	"psexec", "procdump", "laZagne", "gsecdump", "mimikatz.exe",
	"xcopy", "robocopy", "reg", "lsass", "winlogon", "svchost",
}

func isSuspiciousProcess(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range suspiciousProcesses {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
