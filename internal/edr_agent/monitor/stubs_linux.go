//go:build linux

package monitor

import "context"

type WindowsProcMonitor struct{}

func NewWindowsProcMonitor(_ chan<- *Event) *WindowsProcMonitor {
	return &WindowsProcMonitor{}
}

func (*WindowsProcMonitor) Start(_ context.Context) error { return &unsupportedError{} }
func (*WindowsProcMonitor) Stop()                          {}
