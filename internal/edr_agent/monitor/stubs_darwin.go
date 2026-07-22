//go:build darwin

package monitor

import (
	"context"
	"encoding/json"
	"log"
)

type DarwinFileMonitor struct{}

func NewDarwinFileMonitor(_ chan<- *Event) *DarwinFileMonitor {
	return &DarwinFileMonitor{}
}
func (*DarwinFileMonitor) Start(_ context.Context) error {
	log.Printf("[file-mon] darwin: fsevents not available, using polling")
	fm := NewFileMonitor(nil, nil, nil)
	go fm.pollingLoop(context.Background())
	return nil
}
func (*DarwinFileMonitor) Stop() {}

type DarwinProcMonitor struct{}

func NewDarwinProcMonitor(_ chan<- *Event) *DarwinProcMonitor {
	return &DarwinProcMonitor{}
}
func (*DarwinProcMonitor) Start(ctx context.Context) error {
	log.Printf("[proc-mon] darwin: endpoint security not available, using polling")
	pm := NewProcessMonitor(nil)
	pm.Start(ctx)
	return nil
}
func (*DarwinProcMonitor) Stop() {}

type DarwinMemScanner struct{}

func NewDarwinMemScanner() *DarwinMemScanner {
	return &DarwinMemScanner{}
}
func (*DarwinMemScanner) ScanProcess(pid int) ([]*MemoryFinding, error) {
	return nil, nil
}

var _ = json.Marshal
