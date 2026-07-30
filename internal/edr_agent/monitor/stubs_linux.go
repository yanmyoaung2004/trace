//go:build !windows

package monitor

import "context"

type USBMonitor struct{}

func NewUSBMonitor(eventCh chan<- *Event) *USBMonitor { return &USBMonitor{} }
func (m *USBMonitor) Start() error                   { return nil }
func (m *USBMonitor) Stop()                          {}

type HollowingDetector struct{}

func NewHollowingDetector(eventCh chan<- *Event) *HollowingDetector { return &HollowingDetector{} }
func (h *HollowingDetector) Start() error                           { return nil }
func (h *HollowingDetector) Stop()                                  {}

type ETWSession struct{}

func NewETWSession(eventCh chan<- *Event) *ETWSession { return &ETWSession{} }
func (e *ETWSession) Start() error                   { return nil }
func (e *ETWSession) Stop()                          {}

type WindowsProcMonitor struct{}

func NewWindowsProcMonitor(eventCh chan<- *Event) *WindowsProcMonitor { return &WindowsProcMonitor{} }
func (w *WindowsProcMonitor) Start(ctx context.Context) error         { return nil }
func (w *WindowsProcMonitor) Stop()                                   {}

func ScanBufferWithAMSI(content []byte, context string) bool { return false }

type SigningStatus struct {
	Signed       bool
	Trusted      bool
	Publisher    string
	ErrorMessage string
}

func VerifySignature(filePath string) *SigningStatus { return &SigningStatus{Signed: true} }
