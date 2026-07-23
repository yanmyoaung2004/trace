//go:build !windows

package monitor

import "context"

type ETWChannelMonitor struct{}

func NewETWChannelMonitor(eventCh chan<- *Event) *ETWChannelMonitor {
	return &ETWChannelMonitor{}
}

func (m *ETWChannelMonitor) Start(ctx context.Context) error { return nil }

func (m *ETWChannelMonitor) Stop() {}
