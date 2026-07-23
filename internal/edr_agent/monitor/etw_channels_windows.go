//go:build windows

package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ETWChannel struct {
	LogName string
	Query   string
	EventIDs []int
}

type ETWChannelMonitor struct {
	eventCh   chan<- *Event
	channels  []ETWChannel
	interval  time.Duration
	done      chan struct{}
	processed map[string]time.Time
	mu        sync.Mutex
}

var defaultChannels = []ETWChannel{
	{
		LogName:  "Microsoft-Windows-PowerShell/Operational",
		EventIDs: []int{4104, 4103},
		Query:    "*[System[EventID=4104 or EventID=4103]]",
	},
	{
		LogName:  "Microsoft-Windows-Sysmon/Operational",
		EventIDs: []int{1, 2, 3, 7, 8, 11, 12, 13, 15, 22},
		Query:    "*[System[EventID=1 or EventID=2 or EventID=3 or EventID=7 or EventID=8 or EventID=11 or EventID=12 or EventID=13 or EventID=15 or EventID=22]]",
	},
	{
		LogName:  "Microsoft-Windows-TaskScheduler/Operational",
		EventIDs: []int{106, 140, 141},
		Query:    "*[System[EventID=106 or EventID=140 or EventID=141]]",
	},
	{
		LogName:  "System",
		EventIDs: []int{7045},
		Query:    "*[System[EventID=7045]]",
	},
	{
		LogName:  "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
		EventIDs: []int{21, 24},
		Query:    "*[System[EventID=21 or EventID=24]]",
	},
}

func NewETWChannelMonitor(eventCh chan<- *Event) *ETWChannelMonitor {
	return &ETWChannelMonitor{
		eventCh:   eventCh,
		channels:  defaultChannels,
		interval:  10 * time.Second,
		done:      make(chan struct{}),
		processed: make(map[string]time.Time),
	}
}

func (m *ETWChannelMonitor) Start(ctx context.Context) error {
	go m.pollingLoop(ctx)
	return nil
}

func (m *ETWChannelMonitor) Stop() {
	close(m.done)
}

func (m *ETWChannelMonitor) pollingLoop(ctx context.Context) {
	tick := time.NewTicker(m.interval)
	defer tick.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-tick.C:
			m.pollAll()
		}
	}
}

func (m *ETWChannelMonitor) pollAll() {
	for _, ch := range m.channels {
		m.pollChannel(ch)
	}
}

type winEvent struct {
	ID       int                    `json:"id"`
	Time     string                 `json:"time"`
	Level    int                    `json:"level"`
	Provider string                 `json:"provider"`
	LogName  string                 `json:"logname"`
	Message  string                 `json:"message"`
	Properties []map[string]any     `json:"properties"`
}

func (m *ETWChannelMonitor) pollChannel(ch ETWChannel) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Get-WinEvent -LogName '%s' -FilterXPath '%s' -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object {
			[PSCustomObject]@{
				id = $_.Id
				time = $_.TimeCreated.ToString('o')
				level = $_.Level
				provider = $_.ProviderName
				logname = $_.LogName
				message = $_.Message
				properties = @($_.Properties | ForEach-Object { $_.Value })
			}
		} | ConvertTo-Json -Compress -Depth 3`, ch.LogName, ch.Query))

	output, err := cmd.Output()
	if err != nil {
		return
	}

	text := strings.TrimSpace(string(output))
	if text == "" || text == "[]" || text == "null" {
		return
	}

	var events []winEvent
	if err := json.Unmarshal([]byte(text), &events); err != nil {
		return
	}

	for _, we := range events {
		key := ch.LogName + "/" + we.Time
		m.mu.Lock()
		if _, seen := m.processed[key]; seen {
			m.mu.Unlock()
			continue
		}
		m.processed[key] = time.Now()
		m.mu.Unlock()

		m.mapAndEmit(ch, we)
	}
}

func (m *ETWChannelMonitor) mapAndEmit(ch ETWChannel, we winEvent) {
	var evt *Event

	switch we.ID {
	case 4104, 4103:
		// PowerShell script block logging
		script := extractScriptBlock(we)
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityWarning,
			Annotations: map[string]string{
				"source":      "powershell",
				"event_id":    fmt.Sprintf("%d", we.ID),
				"script":      truncate(script, 500),
				"log_channel": ch.LogName,
			},
		}

	case 1:
		// Sysmon process creation
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventProcessCreate,
			Severity:  SeverityInfo,
			Process:   extractSysmonProcess(we),
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "1",
				"log_channel": ch.LogName,
			},
		}

	case 2:
		// Sysmon process changed (handle opened)
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityWarning,
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "2",
				"detail":      "process handle opened",
				"log_channel": ch.LogName,
			},
		}

	case 3:
		// Sysmon network connection
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventNetConnect,
			Severity:  SeverityInfo,
			Network:   extractSysmonNet(we),
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "3",
				"log_channel": ch.LogName,
			},
		}

	case 7:
		// Sysmon image loaded (DLL)
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityWarning,
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "7",
				"detail":      "image loaded",
				"log_channel": ch.LogName,
			},
		}

	case 8:
		// Sysmon remote thread creation
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityAlert,
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "8",
				"detail":      "remote thread created — possible code injection",
				"log_channel": ch.LogName,
			},
		}

	case 11:
		// Sysmon file create
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventFileCreate,
			Severity:  SeverityInfo,
			File:      extractSysmonFile(we),
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "11",
				"log_channel": ch.LogName,
			},
		}

	case 12, 13:
		// Sysmon registry modification
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventRegistryChange,
			Severity:  SeverityWarning,
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    fmt.Sprintf("%d", we.ID),
				"detail":      "registry modification",
				"log_channel": ch.LogName,
			},
		}

	case 15:
		// Sysmon named pipe creation
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityWarning,
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "15",
				"detail":      "named pipe created",
				"log_channel": ch.LogName,
			},
		}

	case 22:
		// Sysmon DNS query
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityInfo,
			Annotations: map[string]string{
				"source":      "sysmon",
				"event_id":    "22",
				"detail":      "DNS query",
				"log_channel": ch.LogName,
			},
		}

	case 106:
		// Task Scheduler task created
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityWarning,
			Annotations: map[string]string{
				"source":      "taskscheduler",
				"event_id":    "106",
				"detail":      "scheduled task created",
				"log_channel": ch.LogName,
			},
		}

	case 7045:
		// Service installed
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityAlert,
			Annotations: map[string]string{
				"source":      "service_control",
				"event_id":    "7045",
				"detail":      "service installed",
				"log_channel": ch.LogName,
			},
		}

	case 21, 24:
		// RDP login/logout
		evt = &Event{
			ID:        uuid.New().String(),
			Timestamp: parseTime(we.Time),
			Type:      EventAlert,
			Severity:  SeverityWarning,
			Annotations: map[string]string{
				"source":      "terminal_services",
				"event_id":    fmt.Sprintf("%d", we.ID),
				"detail":      "RDP session event",
				"log_channel": ch.LogName,
			},
		}

	default:
		return
	}

	if evt != nil {
		select {
		case m.eventCh <- evt:
		default:
		}
	}
}

func extractScriptBlock(we winEvent) string {
	if len(we.Properties) > 0 {
		if v, ok := we.Properties[0]["Value"]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return we.Message
}

func extractSysmonProcess(we winEvent) *ProcessInfo {
	pi := &ProcessInfo{}
	if len(we.Properties) >= 6 {
		if s, ok := we.Properties[4]["Value"].(string); ok {
			pi.Name = s
		}
	}
	// Fallback: try to parse from message
	if pi.Name == "" {
		pi.Name = extractFromMessage(we.Message, "Image:")
	}
	return pi
}

func extractSysmonNet(we winEvent) *NetInfo {
	return &NetInfo{
		Direction: "outbound",
		Protocol:  "tcp",
	}
}

func extractSysmonFile(we winEvent) *FileInfo {
	return &FileInfo{
		Path: extractFromMessage(we.Message, "TargetFilename:"),
	}
}

func extractFromMessage(msg, prefix string) string {
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Now().UTC()
		}
	}
	return t.UTC()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
