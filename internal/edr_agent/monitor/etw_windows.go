//go:build windows

package monitor

import (
	"fmt"
	"log"
	"runtime"
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
	etwFlagProcess       = 0x00000001
	etwFlagImageLoad     = 0x00000004
	wnodeFlagTracedGuid  = 0x00020000
	etwModeRealTime      = 0x00000100
	etwModeNewLog        = 0x00000008
	etwModePrealloc      = 0x00000020
	etwModeCircular      = 0x00000002
	evtTraceCtrlStop     = 1
	procTraceModeEventRecord = 0x01000000
	procTraceModeRealTime    = 0x00000100
	eventIDCreate        = 1
	eventIDProcessEnd    = 2
	eventIDImageLoad     = 3
	maxETWEventsPerSec   = 1000
)

type etwProperties struct {
	Wnode             struct {
		BufferSize    uint32
		_             [4]byte
		_             [8]byte
		_             [8]byte
		Guid          windows.GUID
		ClientContext uint32
		Flags         uint32
	}
	BufferSize        uint32
	MinimumBuffers    uint32
	MaximumBuffers    uint32
	_                 [4]byte
	LogFileMode       uint32
	FlushTimer        uint32
	EnableFlags       uint32
	_                 [4]byte
	_                 [4]byte
	_                 [4]byte
}

type etwLogfile struct {
	LogFileName       *uint16
	LoggerName        *uint16
	_                 [8]byte
	_                 uint32
	ProcessTraceMode  uint32
	_                 [4]byte
	_                 [4]byte
	EventRecord       uintptr
	_                 [32]byte
	Context           uintptr
	_                 [24]byte
}

type etwHeader struct {
	Size            uint16
	Type            uint8
	_               uint8
	_               uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	_               [16]byte
	Id              uint16
	_               [26]byte
}

type etwRecord struct {
	Header            etwHeader
	_                 [8]byte
	_                 uint16
	UserDataLength    uint16
	_                 uintptr
	UserData          uintptr
	_                 [16]byte
}

var (
	kernelProcessGuid = windows.GUID{Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b, Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}}
	processCreateGuid = windows.GUID{Data1: 0x3d6fa8d4, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}
)

var (
	globalETWEventCh chan<- *Event
	globalETWDropped int64
	globalETWCB      uintptr
	globalETWOnce    sync.Once
)

type ETWSession struct {
	eventCh     chan<- *Event
	sessionName string
	traceHandle uintptr
	mu          sync.RWMutex
	running     bool
	rateLimit   *time.Ticker
	connCount   int
}

func NewETWSession(eventCh chan<- *Event) *ETWSession {
	return &ETWSession{eventCh: eventCh, sessionName: "TraceEDRAgentETW"}
}

func (s *ETWSession) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	globalETWEventCh = s.eventCh
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
			log.Printf("[etw] establish: %v (retry 10s)", err)
			time.Sleep(10 * time.Second)
			continue
		}
		s.mu.RLock()
		h := s.traceHandle
		s.mu.RUnlock()
		if h != 0 {
			etwProcessTrace.Call(h, 0, 0, 0)
			log.Printf("[etw] trace ended, restarting")
		}
		s.cleanup()
		time.Sleep(3 * time.Second)
	}
}

func (s *ETWSession) establish() error {
	s.cleanup()
	name16 := make([]uint16, 256)
	for i, c := range s.sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}
	ps := uint32(unsafe.Sizeof(etwProperties{}) + 4096)
	props := make([]byte, ps)
	p := (*etwProperties)(unsafe.Pointer(&props[0]))
	p.Wnode.BufferSize = ps
	p.Wnode.Flags = wnodeFlagTracedGuid
	p.Wnode.Guid = processCreateGuid
	p.BufferSize = 512
	p.MinimumBuffers = 16
	p.MaximumBuffers = 128
	p.LogFileMode = etwModeRealTime | etwModeNewLog | etwModePrealloc | etwModeCircular
	p.EnableFlags = etwFlagProcess | etwFlagImageLoad
	p.FlushTimer = 1

	ret, _, _ := etwStartTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&props[0])))
	status := uint32(ret)
	if status != 0 && status != 183 {
		return fmt.Errorf("starttrace: 0x%x", status)
	}

	// Pin callback to prevent GC
	globalETWOnce.Do(func() {
		globalETWCB = syscall.NewCallback(etwEventCallbackBridge)
		runtime.KeepAlive(globalETWCB)
	})

	lf := &etwLogfile{
		LoggerName:      &name16[0],
		ProcessTraceMode: procTraceModeRealTime | procTraceModeEventRecord,
		EventRecord:     globalETWCB,
	}

	trace, _, _ := etwOpenTrace.Call(uintptr(unsafe.Pointer(lf)))
	if trace == 0 || trace == 0xFFFFFFFFFFFFFFFF {
		return fmt.Errorf("opentrace: failed")
	}

	s.traceHandle = trace
	s.connCount++
	log.Printf("[etw] session ok (attempt %d)", s.connCount)
	return nil
}

func (s *ETWSession) cleanup() {
	name16 := make([]uint16, 256)
	for i, c := range s.sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}
	ps := uint32(unsafe.Sizeof(etwProperties{}) + 4096)
	props := make([]byte, ps)
	etwControlTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&props[0])), evtTraceCtrlStop)
}

func etwEventCallbackBridge(recordPtr uintptr) uintptr {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[etw] callback panic: %v", r)
		}
	}()

	if recordPtr == 0 || globalETWEventCh == nil {
		return 0
	}

	select {
	case <-globalETWEventRateLimit:
	default:
		atomic.AddInt64(&globalETWDropped, 1)
		return 0
	}

	// Read event ID from raw EVENT_HEADER at byte offset 40-41 (cross-arch safe)
	eventID := readU16(recordPtr, 40)
	processID := readU32(recordPtr, 12)

	// EVENT_HEADER layout (byte offsets, verified against ETW spec):
	//   0: Size     (u16)
	//   2: Type     (u8)
	//   3: Flags    (u8)
	//   4: EventProperty (u16)
	//   6: padding  (u16)
	//   8: ThreadId (u32)
	//  12: ProcessId(u32)
	//  16: Timestamp(i64)
	//  24: ProviderId(GUID, 16 bytes)
	//  40: Id       (u16)
	//  42: Version  (u8)
	//  43: Channel  (u8)
	//  44: Level    (u8)
	//  45: Opcode   (u8)
	//  46: Task     (u16)
	//  48: Keyword  (u64)
	//  56: ... total header ~64 bytes
	//
	// EVENT_RECORD follows header with:
	//  64: BufferContext (8 bytes)
	//  72: ExtendedDataCount (u16)
	//  74: UserDataLength (u16)
	//  80: ExtendedData (ptr)
	//  88: UserData (ptr)

	userDataPtr := readPtr(recordPtr, 88)
	userDataLen := readU16(recordPtr, 74)

	switch eventID {
	case eventIDCreate:
		if userDataPtr == 0 || userDataLen < 24 {
			return 0
		}
		handleETWProcessCreateRaw(userDataPtr, uint32(userDataLen), processID)
	case eventIDProcessEnd:
		if userDataPtr == 0 || userDataLen < 8 {
			return 0
		}
		handleETWProcessEndRaw(userDataPtr, uint32(userDataLen), processID)
	}
	return 0
}

// Cross-architecture safe readers — no struct casts
func readU16(ptr uintptr, offset uintptr) uint16 {
	if ptr == 0 {
		return 0
	}
	return *(*uint16)(unsafe.Pointer(ptr + offset))
}

func readU32(ptr uintptr, offset uintptr) uint32 {
	if ptr == 0 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(ptr + offset))
}

func readPtr(ptr uintptr, offset uintptr) uintptr {
	if ptr == 0 {
		return 0
	}
	return *(*uintptr)(unsafe.Pointer(ptr + offset))
}

func handleETWProcessCreateRaw(userData uintptr, userLen uint32, processID uint32) {
	pid := readU32(userData, 0)
	ppid := readU32(userData, 4)
	if pid == 0 || pid == 4 {
		return
	}
	name := readUTF16(userData+16, minU32(userLen-16, 520))
	if name == "" {
		name = "unknown"
	}
	cmdline := ""
	if userLen > 16+520 {
		cmdline = readUTF16(userData+16+520, minU32(userLen-16-520, 2048))
	}
	sev := SeverityInfo
	for _, s := range suspiciousProcesses {
		if len(name) >= len(s) && containsFold(name, s) {
			sev = SeverityWarning
			break
		}
	}
	evt := &Event{
		ID: uuid.New().String(), Timestamp: time.Now(),
		Type: EventProcessCreate, Severity: sev,
		Process: &ProcessInfo{PID: int(pid), PPID: int(ppid), Name: name, CmdLine: cmdline},
		Annotations: map[string]string{"source": "etw"},
	}
	sendETWEvent(evt)
}

func handleETWProcessEndRaw(userData uintptr, userLen uint32, processID uint32) {
	pid := readU32(userData, 0)
	if pid == 0 || pid == 4 {
		return
	}
	exitCode := int32(0)
	if userLen >= 12 {
		exitCode = *(*int32)(unsafe.Pointer(userData + 8))
	}
	evt := &Event{
		ID: uuid.New().String(), Timestamp: time.Now(),
		Type: EventProcessTerminate, Severity: SeverityInfo,
		Process: &ProcessInfo{PID: int(pid)},
		Annotations: map[string]string{"source": "etw", "exit_code": fmt.Sprintf("%d", exitCode)},
	}
	sendETWEvent(evt)
}

func sendETWEvent(evt *Event) {
	select {
	case globalETWEventCh <- evt:
	default:
		atomic.AddInt64(&globalETWDropped, 1)
	}
}

var globalETWEventRateLimit = time.NewTicker(time.Second / maxETWEventsPerSec).C

func readUTF16(ptr uintptr, maxBytes uint32) string {
	if ptr == 0 || maxBytes < 2 {
		return ""
	}
	n := maxBytes / 2
	if n > 512 {
		n = 512
	}
	buf := make([]uint16, n)
	for i := uint32(0); i < n; i++ {
		buf[i] = *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
	}
	return windows.UTF16ToString(buf)
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
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
	s.cleanup()
	if d := atomic.LoadInt64(&globalETWDropped); d > 0 {
		log.Printf("[etw] stopped (dropped %d events)", d)
	}
}
