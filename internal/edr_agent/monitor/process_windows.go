//go:build windows

package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type WindowsProcMonitor struct {
	eventCh      chan<- *Event
	done         chan struct{}
	mu           sync.Mutex
	started      bool
	pollFallback bool
	poller       *ProcessMonitor
}

func NewWindowsProcMonitor(eventCh chan<- *Event) *WindowsProcMonitor {
	return &WindowsProcMonitor{
		eventCh: eventCh,
		done:    make(chan struct{}),
	}
}

func (pm *WindowsProcMonitor) Start(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.started {
		return nil
	}

	// Try ETW-based subscription via PowerShell (Win 8+)
	// Falls back to WMI polling if ETW unavailable
	if err := pm.startETW(); err != nil {
		log.Printf("[proc-mon] ETW unavailable: %v", err)
		return pm.startFallback()
	}

	pm.started = true
	return nil
}

func (pm *WindowsProcMonitor) startETW() error {
	// Use Windows Event Log subscription for Event ID 4688 (process creation)
	// This is more efficient than polling and provides real-time events
	cmd := exec.Command("powershell", "-Command", `
		$query = @'
		<QueryList><Query Id="0">
			<Select Path="Security">*[System[EventID=4688]]</Select>
		</Query></QueryList>
		'@

		$events = @()
		$elapsed = 0
		$timeout = 5000

		while ($elapsed -lt $timeout) {
			$evts = Get-WinEvent -FilterXml $query -MaxEvents 5 -ErrorAction SilentlyContinue
			foreach ($e in $evts) {
				$events += @{
					id = $e.Id
					time = $e.TimeCreated.ToString('o')
					pid = $e.Properties[4].Value
					ppid = $e.Properties[8].Value
					name = $e.Properties[5].Value
					cmdline = $e.Properties[9].Value
				}
			}
			if ($events.Count -gt 0) { break }
			Start-Sleep -Milliseconds 100
			$elapsed += 100
		}

		ConvertTo-Json -Compress $events
	`)

	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("ETW query failed: %w", err)
	}

	go pm.eventPollLoop()

	log.Printf("[proc-mon] Windows EventLog subscription active")
	return nil
}

func (pm *WindowsProcMonitor) eventPollLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastTime := time.Now().UTC().Format(time.RFC3339)

	for {
		select {
		case <-pm.done:
			return
		case <-ticker.C:
			events := pm.pollEvents(lastTime)
			if len(events) > 0 {
				lastTime = time.Now().UTC().Format(time.RFC3339)
				for _, evt := range events {
					pm.emitEvent(evt)
				}
			}
		}
	}
}

type procEventJSON struct {
	ID      int    `json:"id"`
	Time    string `json:"time"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	CmdLine string `json:"cmdline"`
}

func (pm *WindowsProcMonitor) pollEvents(after string) []*procEventJSON {
	// Use wevtutil for faster querying without PowerShell overhead
	cmd := exec.Command("wevtutil", "qe", "Security", "/q:", fmt.Sprintf(
		"*[System[EventID=4688 and TimeCreated[timediff(@SystemTime) <= 5]]]"),
		"/c:10", "/f:text")

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse wevtutil text output
	lines := strings.Split(string(output), "\n")
	events := make([]*procEventJSON, 0)

	var current struct {
		pid    int
		name   string
		cmdline string
		found  bool
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Process ID:") {
			fmt.Sscanf(line, "Process ID: %x", &current.pid)
			current.found = true
		} else if strings.HasPrefix(line, "New Process Name:") {
			current.name = strings.TrimPrefix(line, "New Process Name:")
			current.name = strings.TrimSpace(current.name)
		} else if strings.HasPrefix(line, "CommandLine:") {
			current.cmdline = strings.TrimPrefix(line, "CommandLine:")
			current.cmdline = strings.TrimSpace(current.cmdline)
		} else if strings.HasPrefix(line, "Creator Process ID:") {
			var ppid int
			fmt.Sscanf(line, "Creator Process ID: %x", &ppid)
			if current.found && current.pid > 0 {
				events = append(events, &procEventJSON{
					PID:     current.pid,
					PPID:    ppid,
					Name:    current.name,
					CmdLine: current.cmdline,
				})
			}
			current = struct {
				pid    int
				name   string
				cmdline string
				found  bool
			}{}
		}
	}

	// Fallback: use PowerShell if wevtutil parsing returned nothing
	// (wevtutil output is locale-dependent; Get-WinEvent properties are not)
	if len(events) == 0 {
		events = pm.pollEventsPowerShell(after)
		if events == nil {
			log.Printf("[proc-mon] wevtutil + PowerShell both failed (locale issue?)")
		}
	}

	return events
}

func (pm *WindowsProcMonitor) pollEventsPowerShell(after string) []*procEventJSON {
	psCmd := fmt.Sprintf(`
		$after = [DateTime]::Parse('%s')
		$events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=$after} -MaxEvents 10 -ErrorAction SilentlyContinue
		$result = $events | ForEach-Object {
			[PSCustomObject]@{
				pid = $_.Properties[4].Value
				ppid = $_.Properties[8].Value
				name = $_.Properties[5].Value
				cmdline = $_.Properties[9].Value
			}
		}
		ConvertTo-Json -Compress $result
	`, after)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil || len(output) < 3 {
		return nil
	}

	var events []*procEventJSON
	if err := json.Unmarshal(output, &events); err != nil {
		return nil
	}
	return events
}

func (pm *WindowsProcMonitor) emitEvent(pe *procEventJSON) {
	sev := SeverityInfo
	for _, s := range suspiciousProcesses {
		if strings.Contains(strings.ToLower(pe.Name), s) {
			sev = SeverityWarning
			break
		}
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventProcessCreate,
		Severity:  sev,
		Process: &ProcessInfo{
			PID:     pe.PID,
			Name:    pe.Name,
			CmdLine: pe.CmdLine,
		},
	}

	select {
	case pm.eventCh <- evt:
	default:
	}
}

func (pm *WindowsProcMonitor) startFallback() error {
	log.Printf("[proc-mon] falling back to WMI polling (5s)")
	pm.poller = NewProcessMonitor(pm.eventCh)
	pm.poller.interval = 5 * time.Second
	pm.pollFallback = true
	pm.started = true
	return nil
}

func (pm *WindowsProcMonitor) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.started {
		close(pm.done)
	}
}
