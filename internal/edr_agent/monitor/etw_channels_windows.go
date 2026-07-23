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
	LogName  string
	Query    string
	EventIDs []int
}

type ETWChannelMonitor struct {
	eventCh    chan<- *Event
	channels   []ETWChannel
	interval   time.Duration
	cmdTimeout time.Duration
	done       chan struct{}
	processed  map[string]time.Time
	maxDedup   int
	mu         sync.Mutex
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
		eventCh:    eventCh,
		channels:   defaultChannels,
		interval:   10 * time.Second,
		cmdTimeout: 30 * time.Second,
		done:       make(chan struct{}),
		processed:  make(map[string]time.Time),
		maxDedup:   50000,
	}
}

func (m *ETWChannelMonitor) Start(ctx context.Context) error {
	go m.pollingLoop()
	return nil
}

func (m *ETWChannelMonitor) Stop() {
	close(m.done)
}

func (m *ETWChannelMonitor) pollingLoop() {
	tick := time.NewTicker(m.interval)
	defer tick.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-tick.C:
			m.evictStaleDedup()
			m.pollAll()
		}
	}
}

func (m *ETWChannelMonitor) evictStaleDedup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.processed) <= m.maxDedup {
		return
	}
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, v := range m.processed {
		if v.Before(cutoff) {
			delete(m.processed, k)
		}
	}
}

func (m *ETWChannelMonitor) pollAll() {
	for _, ch := range m.channels {
		m.pollChannel(ch)
	}
}

type winEvent struct {
	ID         int                    `json:"id"`
	Time       string                 `json:"time"`
	Level      int                    `json:"level"`
	Provider   string                 `json:"provider"`
	LogName    string                 `json:"logname"`
	Message    string                 `json:"message"`
	Properties []any                  `json:"properties"`
}

func (m *ETWChannelMonitor) pollChannel(ch ETWChannel) {
	ctx, cancel := context.WithTimeout(context.Background(), m.cmdTimeout)
	defer cancel()

	psCmd := fmt.Sprintf(
		`Get-WinEvent -LogName '%s' -FilterXPath '%s' -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object {
			[PSCustomObject]@{
				id = $_.Id; time = $_.TimeCreated.ToString('o'); level = $_.Level;
				provider = $_.ProviderName; logname = $_.LogName; message = $_.Message;
				properties = @($_.Properties | ForEach-Object { $_.Value })
			}
		} | ConvertTo-Json -Compress -Depth 2`,
		ch.LogName, ch.Query)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psCmd)
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
		key := ch.LogName + "/" + we.Time + "/" + fmt.Sprintf("%d", we.ID)
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
	props := we.Properties

	switch we.ID {
	case 4104, 4103:
		script := ""
		if len(props) > 0 {
			if s, ok := props[0].(string); ok {
				script = truncate(s, 500)
			}
		}
		m.emit(EventAlert, SeverityWarning, map[string]string{
			"source": "powershell", "event_id": fmt.Sprintf("%d", we.ID),
			"script": script, "log_channel": ch.LogName,
		})

	case 1:
		pi := &ProcessInfo{}
		if len(props) >= 6 {
			if s, ok := props[4].(string); ok {
				pi.Name = s
			}
		}
		evt := &Event{
			ID: uuid.New().String(), Timestamp: parseTime(we.Time),
			Type: EventProcessCreate, Severity: SeverityInfo, Process: pi,
			Annotations: map[string]string{"source": "sysmon", "event_id": "1", "log_channel": ch.LogName},
		}
		select { case m.eventCh <- evt: default: }

	case 3:
		evt := &Event{
			ID: uuid.New().String(), Timestamp: parseTime(we.Time),
			Type: EventNetConnect, Severity: SeverityInfo,
			Network: &NetInfo{Direction: "outbound", Protocol: "tcp"},
			Annotations: map[string]string{"source": "sysmon", "event_id": "3", "log_channel": ch.LogName},
		}
		select { case m.eventCh <- evt: default: }

	case 8:
		m.emit(EventAlert, SeverityAlert, map[string]string{
			"source": "sysmon", "event_id": "8",
			"detail": "remote thread created — possible code injection",
			"log_channel": ch.LogName,
		})

	case 11:
		m.emit(EventFileCreate, SeverityInfo, map[string]string{
			"source": "sysmon", "event_id": "11", "log_channel": ch.LogName,
		})

	case 106:
		m.emit(EventAlert, SeverityWarning, map[string]string{
			"source": "taskscheduler", "event_id": "106",
			"detail": "scheduled task created", "log_channel": ch.LogName,
		})

	case 7045:
		m.emit(EventAlert, SeverityAlert, map[string]string{
			"source": "service_control", "event_id": "7045",
			"detail": "service installed", "log_channel": ch.LogName,
		})

	case 21, 24:
		m.emit(EventAlert, SeverityWarning, map[string]string{
			"source": "terminal_services", "event_id": fmt.Sprintf("%d", we.ID),
			"detail": "RDP session event", "log_channel": ch.LogName,
		})
	}
}

func (m *ETWChannelMonitor) emit(etype EventType, sev Severity, annotations map[string]string) {
	evt := &Event{
		ID: uuid.New().String(), Timestamp: time.Now().UTC(),
		Type: etype, Severity: sev, Annotations: annotations,
	}
	select {
	case m.eventCh <- evt:
	default:
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err == nil {
		return t.UTC()
	}
	t, err = time.Parse(time.RFC3339, s)
	if err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}
