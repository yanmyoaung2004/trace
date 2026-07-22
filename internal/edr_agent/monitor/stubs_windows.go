//go:build windows

package monitor

import "context"

type LinuxProcMonitor struct{}

func NewLinuxProcMonitor(_ chan<- *Event) *LinuxProcMonitor {
	return &LinuxProcMonitor{}
}

func (*LinuxProcMonitor) Start(_ context.Context) error { return &unsupportedError{} }
func (*LinuxProcMonitor) Stop()                          {}
