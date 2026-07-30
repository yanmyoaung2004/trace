//go:build !windows

package monitor

// USBMonitor is not available on Linux.
type USBMonitor struct{}

func NewUSBMonitor(eventCh chan<- *Event) *USBMonitor { return &USBMonitor{} }
func (m *USBMonitor) Start() error                   { return nil }
func (m *USBMonitor) Stop()                          {}

// HollowingDetector is not available on Linux.
type HollowingDetector struct{}

func NewHollowingDetector(eventCh chan<- *Event) *HollowingDetector { return &HollowingDetector{} }
func (h *HollowingDetector) Start() error                           { return nil }
func (h *HollowingDetector) Stop()                                  {}

// ETWSession is not available on Linux.
type ETWSession struct{}

func NewETWSession(eventCh chan<- *Event) *ETWSession { return &ETWSession{} }
func (e *ETWSession) Start() error                   { return nil }
func (e *ETWSession) Stop()                          {}

// ScanBufferWithAMSI is not available on Linux.
func ScanBufferWithAMSI(content []byte, context string) bool { return false }

// SigningStatus holds the result of Authenticode verification (Windows only).
type SigningStatus struct {
	Signed       bool
	Trusted      bool
	Publisher    string
	ErrorMessage string
}

// VerifySignature is not available on Linux.
func VerifySignature(filePath string) *SigningStatus { return &SigningStatus{Signed: true} }
