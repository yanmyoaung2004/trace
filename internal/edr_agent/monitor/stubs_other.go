//go:build !linux && !windows

package monitor

import "context"

type LinuxProcMonitor struct{}
type WindowsProcMonitor struct{}

func NewLinuxProcMonitor(_ chan<- *Event) *LinuxProcMonitor {
	return &LinuxProcMonitor{}
}

func NewWindowsProcMonitor(_ chan<- *Event) *WindowsProcMonitor {
	return &WindowsProcMonitor{}
}

func (*LinuxProcMonitor) Start(_ context.Context) error    { return &unsupportedError{} }
func (*WindowsProcMonitor) Start(_ context.Context) error  { return &unsupportedError{} }
func (*LinuxProcMonitor) Stop()                            {}
func (*WindowsProcMonitor) Stop()                          {}

type FanotifyMonitor struct{}
type InotifyFileMonitor struct{}
func NewFanotifyMonitor(_ chan<- *Event) *FanotifyMonitor { return &FanotifyMonitor{} }
func NewInotifyFileMonitor(_ chan<- *Event, _, _ []string) *InotifyFileMonitor { return &InotifyFileMonitor{} }
func (*FanotifyMonitor) Start() error { return &unsupportedError{} }
func (*InotifyFileMonitor) Start(_ context.Context) error { return &unsupportedError{} }
func (*FanotifyMonitor) Stop() {}
func (*InotifyFileMonitor) Stop() {}
