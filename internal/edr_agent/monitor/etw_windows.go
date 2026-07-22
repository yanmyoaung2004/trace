//go:build windows

package monitor

import (
	"fmt"
	"log"
	"sync"
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
	evtTraceCtrlStop  = 1
	procTraceModeEventRecord = 0x01000000
	procTraceModeRealTime    = 0x00000100
	eventIDCreate     = 1
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

var kernelProcessGuid = windows.GUID{
	Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b,
	Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
}

var processCreateGuid = windows.GUID{
	Data1: 0x3d6fa8d4, Data2: 0xfe05, Data3: 0x11d0,
	Data4: [8]byte{0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c},
}

var globalETWEventCh chan<- *Event

type ETWSession struct {
	eventCh     chan<- *Event
	sessionName string
	props       []byte
	traceHandle uintptr
	mu          sync.Mutex
	running     bool
}

func NewETWSession(eventCh chan<- *Event) *ETWSession {
	return &ETWSession{
		eventCh:     eventCh,
		sessionName: "TraceEDRAgentETW",
	}
}

func (s *ETWSession) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}

	globalETWEventCh = s.eventCh

	name16 := make([]uint16, 256)
	for i, c := range s.sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}

	propsSize := uint32(unsafe.Sizeof(etwProperties{}) + 1024)
	s.props = make([]byte, propsSize)
	p := (*etwProperties)(unsafe.Pointer(&s.props[0]))
	p.Wnode.BufferSize = propsSize
	p.Wnode.Flags = wnodeFlagTracedGuid
	p.Wnode.Guid = processCreateGuid
	p.BufferSize = 256
	p.MinimumBuffers = 8
	p.MaximumBuffers = 64
	p.LogFileMode = etwModeRealTime | etwModeNewLog | etwModePrealloc
	p.EnableFlags = etwFlagProcess | etwFlagImageLoad

	ret, _, _ := etwStartTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&s.props[0])))
	status := uint32(ret)
	if status != 0 && status != 183 {
		return errETW(status)
	}

	cb := syscall.NewCallback(etwEventCallback)

	lf := &etwLogfile{
		LoggerName:      &name16[0],
		ProcessTraceMode: procTraceModeRealTime | procTraceModeEventRecord,
		EventRecord:     cb,
	}

	trace, _, _ := etwOpenTrace.Call(uintptr(unsafe.Pointer(lf)))
	if trace == 0 || trace == 0xFFFFFFFFFFFFFFFF {
		etwControlTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&s.props[0])), evtTraceCtrlStop)
		return errETW(0xFFFFFFFF)
	}

	s.traceHandle = trace
	s.running = true

	go func() {
		etwProcessTrace.Call(trace, 0, 0, 0)
	}()

	log.Printf("[etw] session active")
	return nil
}

func etwEventCallback(recordPtr uintptr) uintptr {
	if recordPtr == 0 || globalETWEventCh == nil {
		return 0
	}
	rec := (*etwRecord)(unsafe.Pointer(recordPtr))
	if rec.Header.Id != eventIDCreate || rec.UserData == 0 || rec.UserDataLength < 24 {
		return 0
	}

	pid := *(*uint32)(unsafe.Pointer(rec.UserData))
	ppid := *(*uint32)(unsafe.Pointer(rec.UserData + 4))

	nameLen := rec.UserDataLength - 16
	if nameLen > 520 {
		nameLen = 520
	}
	namePtr := rec.UserData + 16
	nameBuf := make([]uint16, nameLen/2)
	for i := 0; i < len(nameBuf) && uintptr(i*2) < uintptr(nameLen); i++ {
		nameBuf[i] = *(*uint16)(unsafe.Pointer(namePtr + uintptr(i*2)))
	}
	name := windows.UTF16ToString(nameBuf)

	cmdline := ""
	if rec.UserDataLength > 16+520 {
		cmdPtr := rec.UserData + 16 + 520
		cmdLen := rec.UserDataLength - 16 - 520
		if cmdLen > 2048 {
			cmdLen = 2048
		}
		cmdBuf := make([]uint16, cmdLen/2)
		for i := 0; i < len(cmdBuf) && uintptr(i*2) < uintptr(cmdLen); i++ {
			cmdBuf[i] = *(*uint16)(unsafe.Pointer(cmdPtr + uintptr(i*2)))
		}
		cmdline = windows.UTF16ToString(cmdBuf)
	}

	sev := SeverityInfo
	for _, s := range suspiciousProcesses {
		if len(name) >= len(s) {
			match := true
			for j := 0; j < len(s) && j < len(name); j++ {
				a, b := name[j], s[j]
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
				sev = SeverityWarning
				break
			}
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
	}
	return 0
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

	name16 := make([]uint16, 256)
	for i, c := range s.sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}
	propSize := uint32(unsafe.Sizeof(etwProperties{}) + 1024)
	props := make([]byte, propSize)
	etwControlTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&props[0])), evtTraceCtrlStop)

	log.Printf("[etw] session stopped")
}

func errETW(status uint32) error {
	switch status {
	case 0:
		return errorf("etw: success (unexpected)")
	case 2:
		return errorf("etw: system cannot find file")
	case 5:
		return errorf("etw: access denied")
	case 87:
		return errorf("etw: invalid parameter")
	case 183:
		return errorf("etw: session already exists")
	case 0xFFFFFFFF:
		return errorf("etw: open trace failed")
	default:
		return errorf("etw: status 0x%x", status)
	}
}

func errorf(format string, args ...any) error {
	return &etwError{s: fmt.Sprintf(format, args...)}
}

type etwError struct{ s string }
func (e *etwError) Error() string { return e.s }
