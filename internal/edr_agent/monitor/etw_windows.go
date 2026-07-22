//go:build windows

package monitor

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

var (
	etwAdvapi32         = windows.NewLazySystemDLL("advapi32.dll")
	etwStartTrace       = etwAdvapi32.NewProc("StartTraceW")
	etwOpenTrace        = etwAdvapi32.NewProc("OpenTraceW")
	etwProcessTrace     = etwAdvapi32.NewProc("ProcessTrace")
	etwCloseTrace       = etwAdvapi32.NewProc("CloseTrace")
	etwControlTrace     = etwAdvapi32.NewProc("ControlTraceW")
)

const (
	etwFlagProcess   = 0x00000001
	etwFlagImageLoad = 0x00000004
	wnodeFlagTracedGuid = 0x00020000
	etwModeRealTime   = 0x00000100
	etwModeNewLog     = 0x00000008
	etwModePrealloc   = 0x00000020
	etwModeCircular   = 0x00000002
	evtTraceCtrlStop  = 1
	evtTraceCtrlFlush = 3
	procTraceModeEventRecord = 0x01000000
	procTraceModeRealTime    = 0x00000100
	eventIDCreate     = 1
	maxETWEventsPerSec = 1000
)

type etwNodeHeader struct {
	BufferSize    uint32
	_             [4]byte
	_             [8]byte
	_             [8]byte
	Guid          windows.GUID
	ClientContext uint32
	Flags         uint32
}

type etwProperties struct {
	Wnode             etwNodeHeader
	BufferSize        uint32
	MinimumBuffers    uint32
	MaximumBuffers    uint32
	MaximumFileSize   uint32
	LogFileMode       uint32
	FlushTimer        uint32
	EnableFlags       uint32
	_                 [4]byte
	LogFileNameOffset uint32
	LoggerNameOffset  uint32
}

type etwLogfile struct {
	LogFileName       *uint16
	LoggerName        *uint16
	CurrentTime       int64
	BuffersRead       uint32
	ProcessTraceMode  uint32
	CurrentClient     uint32
	LogFileMode       uint32
	OffsetInfo        uint32
	EventRecord       uintptr
	BufferContext     [4]uint32
	_                 [24]byte
	Context           uintptr
	_                 [8]byte
	_                 [16]byte
}

type etwHeader struct {
	Size            uint16
	Type            uint8
	Flags           uint8
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      [16]byte
	Id              uint16
	Version         uint8
	Channel         uint8
	Level           uint8
	Opcode          uint8
	Task            uint16
	Keyword         uint64
	_               [24]byte
}

type etwRecord struct {
	Header            etwHeader
	_                 [8]byte
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	_                 [16]byte
}

var kernelProcessGuid = windows.GUID{
	Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b,
	Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
}

var processCreateGuid = windows.GUID{
	Data1: 0x3d6fa8d4, Data2: 0xfe05, Data3: 0x11d0,
	Data4: [8]byte{0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c},
}

var (
	globalETWEventCh  chan<- *Event
	globalETWDropped  int64
	globalETWSessName string
)

type ETWSession struct {
	eventCh     chan<- *Event
	sessionName string
	props       []byte
	traceHandle uintptr
	mu          sync.RWMutex
	running     bool
	restartCh   chan struct{}
	stopCh      chan struct{}
	rateLimit   *time.Ticker
	connCount   int
}

func NewETWSession(eventCh chan<- *Event) *ETWSession {
	return &ETWSession{
		eventCh:     eventCh,
		sessionName: "TraceEDRAgentETW",
		restartCh:   make(chan struct{}, 1),
		stopCh:      make(chan struct{}),
	}
}

func (s *ETWSession) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}

	globalETWEventCh = s.eventCh
	globalETWSessName = s.sessionName
	s.running = true
	s.rateLimit = time.NewTicker(time.Second / maxETWEventsPerSec)

	go s.connLoop()

	return nil
}

func (s *ETWSession) connLoop() {
	for {
		s.mu.RLock()
		if !s.running {
			s.mu.RUnlock()
			return
		}
		s.mu.RUnlock()

		if err := s.establish(); err != nil {
			log.Printf("[etw] establish failed: %v (retry in 10s)", err)
			time.Sleep(10 * time.Second)
			continue
		}

		// ProcessTrace blocks until trace ends
		s.mu.RLock()
		h := s.traceHandle
		s.mu.RUnlock()

		if h != 0 {
			log.Printf("[etw] processing trace events...")
			etwProcessTrace.Call(h, 0, 0, 0)
			log.Printf("[etw] trace ended (server disconnected? restarting...)")
		}

		s.mu.Lock()
		s.traceHandle = 0
		s.mu.Unlock()

		s.cleanupSession()
		time.Sleep(3 * time.Second)
	}
}

func (s *ETWSession) establish() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupSession()

	name16 := make([]uint16, 256)
	for i, c := range s.sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}

	propsSize := uint32(unsafe.Sizeof(etwProperties{}) + 4096)
	s.props = make([]byte, propsSize)
	p := (*etwProperties)(unsafe.Pointer(&s.props[0]))
	p.Wnode.BufferSize = propsSize
	p.Wnode.Flags = wnodeFlagTracedGuid
	p.Wnode.Guid = processCreateGuid
	p.BufferSize = 512
	p.MinimumBuffers = 16
	p.MaximumBuffers = 128
	p.LogFileMode = etwModeRealTime | etwModeNewLog | etwModePrealloc | etwModeCircular
	p.EnableFlags = etwFlagProcess | etwFlagImageLoad
	p.FlushTimer = 1

	ret, _, _ := etwStartTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&s.props[0])))
	status := uint32(ret)
	if status != 0 && status != 183 {
		return etwErr(status)
	}

	cb := syscall.NewCallback(etwEventCallback)

	lf := &etwLogfile{
		LoggerName:      &name16[0],
		ProcessTraceMode: procTraceModeRealTime | procTraceModeEventRecord,
		EventRecord:     cb,
		Context:          uintptr(unsafe.Pointer(s)),
	}

	trace, _, _ := etwOpenTrace.Call(uintptr(unsafe.Pointer(lf)))
	if trace == 0 || trace == 0xFFFFFFFFFFFFFFFF {
		s.cleanupSession()
		return etwErr(0xFFFFFFFF)
	}

	s.traceHandle = trace
	s.connCount++
	globalETWDropped = 0

	log.Printf("[etw] session established (attempt %d)", s.connCount)
	return nil
}

func (s *ETWSession) cleanupSession() {
	name16 := make([]uint16, 256)
	for i, c := range s.sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}
	propsSize := uint32(unsafe.Sizeof(etwProperties{}) + 4096)
	props := make([]byte, propsSize)
	etwControlTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&props[0])), evtTraceCtrlFlush)
	etwControlTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&props[0])), evtTraceCtrlStop)
}

func etwEventCallback(recordPtr uintptr) uintptr {
	if recordPtr == 0 || globalETWEventCh == nil {
		return 0
	}

	select {
	case <-globalETWEventRateLimit:
	default:
		atomic.AddInt64(&globalETWDropped, 1)
		return 0
	}

	rec := (*etwRecord)(unsafe.Pointer(recordPtr))
	if rec.Header.Id != eventIDCreate || rec.UserData == 0 || rec.UserDataLength < 24 {
		return 0
	}

	pid := *(*uint32)(unsafe.Pointer(rec.UserData))
	ppid := *(*uint32)(unsafe.Pointer(rec.UserData + 4))
	if pid == 0 || pid == 4 {
		return 0
	}

	userLen := uint32(rec.UserDataLength)
	name := extractUTF16(rec.UserData+16, minUint32(userLen-16, 520))
	cmdline := ""
	if userLen > 16+520 {
		cmdline = extractUTF16(rec.UserData+16+520, minUint32(userLen-16-520, 2048))
	}

	sev := SeverityInfo
	for _, s := range suspiciousProcesses {
		if len(name) >= len(s) && caseInsensitiveContains(name, s) {
			sev = SeverityWarning
			break
		}
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventProcessCreate,
		Severity:  sev,
		Process: &ProcessInfo{
			PID: int(pid), PPID: int(ppid), Name: name, CmdLine: cmdline,
		},
		Annotations: map[string]string{"source": "etw"},
	}

	select {
	case globalETWEventCh <- evt:
	default:
		atomic.AddInt64(&globalETWDropped, 1)
	}
	return 0
}

var globalETWEventRateLimit = time.NewTicker(time.Second / maxETWEventsPerSec).C

func extractUTF16(ptr uintptr, maxBytes uint32) string {
	if ptr == 0 || maxBytes < 2 {
		return ""
	}
	count := maxBytes / 2
	if count > 1024 {
		count = 1024
	}
	buf := make([]uint16, count)
	for i := uint32(0); i < count; i++ {
		buf[i] = *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
	}
	return windows.UTF16ToString(buf)
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func caseInsensitiveContains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc, bc := s[i+j], substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if bc >= 'A' && bc <= 'Z' {
				bc += 32
			}
			if sc != bc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (s *ETWSession) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false

	if s.traceHandle != 0 {
		etwCloseTrace.Call(s.traceHandle)
	}
	s.cleanupSession()

	dropped := atomic.LoadInt64(&globalETWDropped)
	if dropped > 0 {
		log.Printf("[etw] stopped (%d events dropped due to rate limit)", dropped)
	}
}

func etwErr(status uint32) error {
	switch status {
	case 0:
		return fmt.Errorf("etw: unexpected success")
	case 2:
		return fmt.Errorf("etw: system cannot find the file specified")
	case 5:
		return fmt.Errorf("etw: access denied (run as administrator)")
	case 87:
		return fmt.Errorf("etw: invalid parameter")
	case 183:
		return nil // already exists — fine
	case 0xFFFFFFFF:
		return fmt.Errorf("etw: open trace failed")
	default:
		return fmt.Errorf("etw: 0x%x", status)
	}
}
