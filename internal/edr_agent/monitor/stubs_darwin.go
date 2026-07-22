//go:build darwin

package monitor

import (
	"context"
	"log"
	"time"
)

type DarwinFileMonitor struct {
	eventCh chan<- *Event
	poller  *FileMonitor
}

func NewDarwinFileMonitor(eventCh chan<- *Event) *DarwinFileMonitor {
	return &DarwinFileMonitor{eventCh: eventCh}
}

func (m *DarwinFileMonitor) Start(ctx context.Context) error {
	log.Printf("[file-mon] darwin: fsevents unavailable, polling /tmp /var/tmp /etc")
	m.poller = NewFileMonitor(m.eventCh, []string{"/tmp", "/var/tmp", "/etc", "/Library/LaunchAgents", "/Users/Shared"}, nil)
	m.poller.Start(ctx)
	return nil
}

func (m *DarwinFileMonitor) Stop() {
	if m.poller != nil {
		m.poller.Stop()
	}
}

type DarwinProcMonitor struct {
	eventCh chan<- *Event
	poller  *ProcessMonitor
}

func NewDarwinProcMonitor(eventCh chan<- *Event) *DarwinProcMonitor {
	return &DarwinProcMonitor{eventCh: eventCh}
}

func (m *DarwinProcMonitor) Start(ctx context.Context) error {
	log.Printf("[proc-mon] darwin: endpoint security unavailable, polling /bin/ps")
	m.poller = NewProcessMonitor(m.eventCh)
	m.poller.interval = 5 * time.Second
	m.poller.Start(ctx)
	return nil
}

func (m *DarwinProcMonitor) Stop() {
	if m.poller != nil {
		m.poller.Stop()
	}
}

type DarwinMemScanner struct {
	eventCh chan<- *Event
}

func NewDarwinMemScanner(eventCh chan<- *Event) *DarwinMemScanner {
	return &DarwinMemScanner{eventCh: eventCh}
}

func (*DarwinMemScanner) ScanProcess(pid int) ([]*MemoryFinding, error) {
	return nil, nil
}
