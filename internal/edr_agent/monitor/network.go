package monitor

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type NetConn struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	Protocol   string
	PID        int
	Process    string
	State      string
}

type NetworkMonitor struct {
	eventCh    chan<- *Event
	interval   time.Duration
	done       chan struct{}
	prevConns  map[string]*NetConn
	mu         sync.Mutex
}

func NewNetworkMonitor(eventCh chan<- *Event, interval time.Duration) *NetworkMonitor {
	return &NetworkMonitor{
		eventCh:   eventCh,
		interval:  interval,
		done:      make(chan struct{}),
		prevConns: make(map[string]*NetConn),
	}
}

func (nm *NetworkMonitor) Start(ctx context.Context) error {
	go nm.pollingLoop(ctx)
	return nil
}

func (nm *NetworkMonitor) Stop() {
	close(nm.done)
}

func (nm *NetworkMonitor) pollingLoop(ctx context.Context) {
	tick := time.NewTicker(nm.interval)
	defer tick.Stop()

	for {
		select {
		case <-nm.done:
			return
		case <-tick.C:
			nm.scan()
		}
	}
}

func (nm *NetworkMonitor) scan() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	current := make(map[string]*NetConn)

	switch runtime.GOOS {
	case "windows":
		nm.readWindows(current)
	case "linux":
		nm.readLinux(current)
	case "darwin":
		nm.readDarwin(current)
	}

	key := func(c *NetConn) string {
		return fmt.Sprintf("%s:%d-%s:%d-%s", c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.Protocol)
	}

	// Detect new connections
	for _, conn := range current {
		k := key(conn)
		if _, exists := nm.prevConns[k]; !exists {
			if conn.RemoteIP != "" && conn.RemoteIP != "*" {
				nm.emitNetEvent(EventNetConnect, conn)
			}
			if conn.State == "LISTEN" || conn.State == "LISTENING" {
				nm.emitNetEvent(EventNetListen, conn)
			}
		}
	}

	// Detect closed connections
	for k, prev := range nm.prevConns {
		if _, exists := current[k]; !exists {
			if prev.RemoteIP != "" && prev.RemoteIP != "*" {
				nm.emitNetEvent(EventNetDisconnect, prev)
			}
		}
	}

	nm.prevConns = current
}

func (nm *NetworkMonitor) readWindows(conns map[string]*NetConn) {
	data, err := exec.Command("powershell", "-Command",
		"netstat -ano | Select-String TCP,UDP").Output()
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		conn := &NetConn{Protocol: strings.ToLower(fields[0])}
		if conn.Protocol == "" {
			continue
		}

		local := fields[1]
		if idx := strings.LastIndex(local, ":"); idx >= 0 {
			conn.LocalIP = local[:idx]
			conn.LocalPort, _ = strconv.Atoi(local[idx+1:])
		}

		remote := fields[2]
		if remote == "*:*" {
			remote = "0.0.0.0:0"
		}
		if idx := strings.LastIndex(remote, ":"); idx >= 0 {
			conn.RemoteIP = remote[:idx]
			conn.RemotePort, _ = strconv.Atoi(remote[idx+1:])
		}

		conn.State = fields[3]
		conn.PID, _ = strconv.Atoi(fields[len(fields)-1])

		conns[fmt.Sprintf("%s:%d", conn.LocalIP, conn.LocalPort)] = conn
	}
}

func (nm *NetworkMonitor) readLinux(conns map[string]*NetConn) {
	data, err := exec.Command("ss", "-tunap").Output()
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		conn := &NetConn{}
		switch fields[0] {
		case "tcp":
			conn.Protocol = "tcp"
		case "udp":
			conn.Protocol = "udp"
		default:
			continue
		}

		conn.State = fields[1]
		local := fields[4]
		if idx := strings.LastIndex(local, ":"); idx >= 0 {
			conn.LocalIP = local[:idx]
			conn.LocalPort, _ = strconv.Atoi(local[idx+1:])
		}

		remote := fields[5]
		if idx := strings.LastIndex(remote, ":"); idx >= 0 {
			conn.RemoteIP = remote[:idx]
			conn.RemotePort, _ = strconv.Atoi(remote[idx+1:])
		}

		if len(fields) > 6 {
			pidStr := fields[6]
			if idx := strings.Index(pidStr, "pid="); idx >= 0 {
				end := strings.Index(pidStr[idx:], ",")
				if end < 0 {
					end = len(pidStr[idx:])
				}
				conn.PID, _ = strconv.Atoi(pidStr[idx+4 : idx+end])
			}
		}

		key := fmt.Sprintf("%s:%d-%s:%d", conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort)
		conns[key] = conn
	}
}

func (nm *NetworkMonitor) readDarwin(conns map[string]*NetConn) {
	data, err := exec.Command("lsof", "-i", "-P", "-n").Output()
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		conn := &NetConn{
			PID:     func() int { p, _ := strconv.Atoi(fields[1]); return p }(),
			Process: fields[0],
		}

		switch fields[4] {
		case "TCP":
			conn.Protocol = "tcp"
		case "UDP":
			conn.Protocol = "udp"
		default:
			continue
		}

		addr := fields[8]
		parts := strings.Split(addr, "->")
		local := parts[0]
		if idx := strings.LastIndex(local, ":"); idx >= 0 {
			conn.LocalIP = local[:idx]
			conn.LocalPort, _ = strconv.Atoi(local[idx+1:])
		}
		if len(parts) > 1 {
			remote := parts[1]
			if idx := strings.LastIndex(remote, ":"); idx >= 0 {
				conn.RemoteIP = remote[:idx]
				conn.RemotePort, _ = strconv.Atoi(remote[idx+1:])
			}
		}

		conns[fmt.Sprintf("%s:%d", conn.LocalIP, conn.LocalPort)] = conn
	}
}

func (nm *NetworkMonitor) emitNetEvent(etype EventType, conn *NetConn) {
	sev := SeverityInfo
	if isSuspiciousConnection(conn) {
		sev = SeverityWarning
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Type:      etype,
		Severity:  sev,
		Network: &NetInfo{
			LocalIP:    conn.LocalIP,
			LocalPort:  conn.LocalPort,
			RemoteIP:   conn.RemoteIP,
			RemotePort: conn.RemotePort,
			Protocol:   conn.Protocol,
			PID:        conn.PID,
			Process:    conn.Process,
			Direction:  func() string { if etype == EventNetListen { return "inbound" }; return "outbound" }(),
		},
	}

	if sev >= SeverityWarning {
		evt.Annotations = map[string]string{"reason": "suspicious_connection"}
	}

	select {
	case nm.eventCh <- evt:
	default:
	}
}

func isSuspiciousConnection(conn *NetConn) bool {
	if conn.RemotePort == 445 || conn.RemotePort == 139 || conn.RemotePort == 135 {
		return true
	}
	if conn.RemotePort == 3389 || conn.RemotePort == 22 || conn.RemotePort == 23 {
		return true
	}
	if conn.LocalPort < 1024 && conn.State == "LISTEN" {
		return false
	}
	return false
}

func init() {
	log.Printf("[net-monitor] initialized for %s", runtime.GOOS)
}
