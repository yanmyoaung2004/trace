//go:build windows

package monitor

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

var (
	wkAdvapi32   = windows.NewLazySystemDLL("advapi32.dll")
	wkStartTrace = wkAdvapi32.NewProc("StartTraceW")
	wkOpenTrace  = wkAdvapi32.NewProc("OpenTraceW")
	wkProcTrace  = wkAdvapi32.NewProc("ProcessTrace")
	wkCloseTrace = wkAdvapi32.NewProc("CloseTrace")
	wkCtrlTrace  = wkAdvapi32.NewProc("ControlTraceW")
)

var codeIntegrityGuid = windows.GUID{
	Data1: 0x4ee76ec7, Data2: 0x1e0a, Data3: 0x48f6,
	Data4: [8]byte{0xaf, 0x60, 0x63, 0xb0, 0xc3, 0xf0, 0xb1, 0xf2},
}

var dnsClientGuid = windows.GUID{
	Data1: 0x1c95126e, Data2: 0x7eea, Data3: 0x49a9,
	Data4: [8]byte{0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d},
}

var (
	globalWinKernelCh    chan<- *Event
	globalWinKernelDrop  int64
	globalCISession      uintptr
	globalDNSSession     uintptr
	globalWKCallback     uintptr
	globalWKOnce         sync.Once
	globalAMSIEnabled    bool
	globalAMSIDll        syscall.Handle
)

type wkProperties struct {
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

type wkLogfile struct {
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

// ── Code Integrity ETW ──

func startCodeIntegrityETW(eventCh chan<- *Event) {
	globalWinKernelCh = eventCh

	name16 := make([]uint16, 256)
	sessionName := "TraceCIETW"
	for i, c := range sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}

	ps := uint32(unsafe.Sizeof(wkProperties{}) + 4096)
	props := make([]byte, ps)
	p := (*wkProperties)(unsafe.Pointer(&props[0]))
	p.Wnode.BufferSize = ps
	p.Wnode.Flags = 0x00020000
	p.Wnode.Guid = codeIntegrityGuid
	p.BufferSize = 256
	p.MinimumBuffers = 4
	p.MaximumBuffers = 32
	p.LogFileMode = 0x00000100 | 0x00000008
	p.EnableFlags = 0

	ret, _, _ := wkStartTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&props[0])))
	status := uint32(ret)
	if status != 0 && status != 183 {
		log.Printf("[ci-etw] start failed: 0x%x", status)
		return
	}

	globalWKOnce.Do(func() {
		globalWKCallback = syscall.NewCallback(ciEventCallback)
	})

	lf := &wkLogfile{
		LoggerName:      &name16[0],
		ProcessTraceMode: 0x01000000 | 0x00000100,
		EventRecord:     globalWKCallback,
	}

	trace, _, _ := wkOpenTrace.Call(uintptr(unsafe.Pointer(lf)))
	if trace == 0 || trace == 0xFFFFFFFFFFFFFFFF {
		log.Printf("[ci-etw] open trace failed")
		return
	}

	globalCISession = trace
	go func() {
		wkProcTrace.Call(trace, 0, 0, 0)
	}()
	log.Printf("[ci-etw] CodeIntegrity monitoring active")
}

func ciEventCallback(recordPtr uintptr) uintptr {
	if recordPtr == 0 || globalWinKernelCh == nil {
		return 0
	}

	rec := (*etwRecord)(unsafe.Pointer(recordPtr))
	// EventID 3001 = unsigned driver blocked, 3004 = unsigned driver allowed
	if rec.Header.Id != 3001 && rec.Header.Id != 3004 {
		return 0
	}
	if rec.UserData == 0 {
		return 0
	}

	driverName := readUTF16(rec.UserData+8, 512)
	if driverName == "" {
		return 0
	}

	blocked := rec.Header.Id == 3001
	sev := SeverityWarning
	if blocked {
		sev = SeverityAlert
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventAlert,
		Severity:  sev,
		File:      &FileInfo{Path: driverName},
		Annotations: map[string]string{
			"source":     "code_integrity",
			"event_id":   fmt.Sprintf("%d", rec.Header.Id),
			"driver":     driverName,
			"blocked":    fmt.Sprintf("%v", blocked),
			"pid":        fmt.Sprintf("%d", rec.Header.ProcessId),
		},
	}

	select {
	case globalWinKernelCh <- evt:
	default:
		atomic.AddInt64(&globalWinKernelDrop, 1)
	}
	return 0
}

// ── DNS Query ETW ──

func startDNSQueryETW(eventCh chan<- *Event) {
	globalWinKernelCh = eventCh

	name16 := make([]uint16, 256)
	sessionName := "TraceDNSETW"
	for i, c := range sessionName {
		if i < 255 {
			name16[i] = uint16(c)
		}
	}

	ps := uint32(unsafe.Sizeof(wkProperties{}) + 4096)
	props := make([]byte, ps)
	p := (*wkProperties)(unsafe.Pointer(&props[0]))
	p.Wnode.BufferSize = ps
	p.Wnode.Flags = 0x00020000
	p.Wnode.Guid = dnsClientGuid
	p.BufferSize = 256
	p.MinimumBuffers = 4
	p.MaximumBuffers = 32
	p.LogFileMode = 0x00000100 | 0x00000008
	p.EnableFlags = 0

	ret, _, _ := wkStartTrace.Call(0, uintptr(unsafe.Pointer(&name16[0])), uintptr(unsafe.Pointer(&props[0])))
	status := uint32(ret)
	if status != 0 && status != 183 {
		log.Printf("[dns-etw] start failed: 0x%x", status)
		return
	}

	cb := syscall.NewCallback(dnsEventCallback)

	lf := &wkLogfile{
		LoggerName:      &name16[0],
		ProcessTraceMode: 0x01000000 | 0x00000100,
		EventRecord:     cb,
	}

	trace, _, _ := wkOpenTrace.Call(uintptr(unsafe.Pointer(lf)))
	if trace == 0 || trace == 0xFFFFFFFFFFFFFFFF {
		log.Printf("[dns-etw] open trace failed")
		return
	}

	globalDNSSession = trace
	go func() {
		wkProcTrace.Call(trace, 0, 0, 0)
	}()
	log.Printf("[dns-etw] DNS-Client monitoring active")
}

func dnsEventCallback(recordPtr uintptr) uintptr {
	if recordPtr == 0 || globalWinKernelCh == nil {
		return 0
	}

	rec := (*etwRecord)(unsafe.Pointer(recordPtr))
	if rec.Header.Id != 3006 && rec.Header.Id != 3008 {
		return 0
	}

	pid := rec.Header.ProcessId
	domain := ""

	if rec.UserData != 0 && rec.UserDataLength > 2 {
		domain = readUTF16(rec.UserData, minU32(uint32(rec.UserDataLength), 512))
	}

	if domain == "" {
		return 0
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventNetConnect,
		Severity:  SeverityInfo,
		Process:   &ProcessInfo{PID: int(pid)},
		Network: &NetInfo{
			RemoteIP:   domain,
			RemotePort: 53,
			Protocol:   "dns",
		},
		Annotations: map[string]string{"source": "dns_etw", "query_type": func() string {
			if rec.Header.Id == 3006 { return "query" }; return "response"
		}()},
	}

	select {
	case globalWinKernelCh <- evt:
	default:
		atomic.AddInt64(&globalWinKernelDrop, 1)
	}
	return 0
}

// ── AMSI Integration ──

func initAMSI() bool {
	if globalAMSIDll != 0 {
		return true
	}

	dll, err := syscall.LoadLibrary("amsi.dll")
	if err != nil {
		log.Printf("[amsi] not available: %v", err)
		return false
	}
	globalAMSIDll = dll
	globalAMSIEnabled = true
	log.Printf("[amsi] initialized")
	return true
}

func scanAMSI(content string, context string) bool {
	if !globalAMSIEnabled || globalAMSIDll == 0 {
		return false
	}

	proc, err := syscall.GetProcAddress(globalAMSIDll, "AmsiScanBuffer")
	if err != nil {
		log.Printf("[amsi] AmsiScanBuffer not found, trying AmsiScanString")
		proc, err = syscall.GetProcAddress(globalAMSIDll, "AmsiScanString")
		if err != nil {
			return false
		}
	}

	amsiContext, err := syscall.UTF16PtrFromString(context)
	if err != nil {
		return false
	}

	contentBytes := []byte(content)
	contentPtr := uintptr(unsafe.Pointer(&contentBytes[0]))
	contentLen := uint32(len(contentBytes))

	var result int32

	syscall.Syscall9(uintptr(proc), 7,
		uintptr(unsafe.Pointer(amsiContext)),
		contentPtr,
		uintptr(contentLen),
		uintptr(unsafe.Pointer(amsiContext)),
		0,
		uintptr(unsafe.Pointer(&result)),
		0, 0, 0)

	return result != 0
}

func ScanPowerShell(content string) bool {
	return scanAMSI(content, "powershell")
}

// ── USB Monitoring ──

const (
	dbtDevTypDeviceInterface = 5
	dbtDevicearrival         = 0x8000
	dbtDeviceremovecomplete  = 0x8004
)

type devBroadcastDeviceInterface struct {
	DbccSize       uint32
	DbccDeviceType uint32
	DbccReserved   uint32
	DbccClassGuid  windows.GUID
	DbccName       [256]uint16
}

type USBMonitor struct {
	eventCh    chan<- *Event
	done       chan struct{}
	started    bool
	mu         sync.Mutex
}

func NewUSBMonitor(eventCh chan<- *Event) *USBMonitor {
	return &USBMonitor{
		eventCh: eventCh,
		done:    make(chan struct{}),
	}
}

func (m *USBMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}
	m.started = true
	log.Printf("[usb] polling for device changes every 30s")
	go m.pollLoop()
	return nil
}

func (m *USBMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = false
	close(m.done)
}

type usbDevice struct {
	DeviceID  string
	VendorID  string
	ProductID string
	Serial    string
	Drive     string
}

func (m *USBMonitor) pollLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()

	known := make(map[string]bool)

	// Initial snapshot
	for _, dev := range pollUSBDevices() {
		known[dev.DeviceID] = true
	}

	for {
		select {
		case <-m.done:
			return
		case <-tick.C:
			current := pollUSBDevices()
			now := map[string]bool{}
			for _, dev := range current {
				now[dev.DeviceID] = true
				if !known[dev.DeviceID] {
					m.emitUSBEvent(dev, true)
				}
			}
			for id := range known {
				if !now[id] {
					m.emitUSBEvent(usbDevice{DeviceID: id}, false)
				}
			}
			known = now
		}
	}
}

func pollUSBDevices() []usbDevice {
	var devices []usbDevice

	// Try PowerShell for detailed info
	data, err := runCmd("powershell", "-NoProfile", "-Command",
		"Get-PnpDevice -Class USB | Where-Object {$_.Status -eq 'OK'} | Select-Object DeviceID, FriendlyName | ConvertTo-Json -Compress")
	if err == nil && len(data) > 5 {
		entries, err := parseUSBJSON(data)
		if err == nil {
			devices = append(devices, entries...)
		}
	}

	// Get drive letters
	driveData, err := runCmd("powershell", "-NoProfile", "-Command",
		"Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2} | Select-Object DeviceID, VolumeName | ConvertTo-Json -Compress")
	if err == nil && len(driveData) > 5 {
		drives := parseDriveInfo(driveData)
		for _, d := range drives {
			found := false
			for i := range devices {
				if devices[i].Drive == "" {
					devices[i].Drive = d
					found = true
					break
				}
			}
			if !found {
				devices = append(devices, usbDevice{DeviceID: "USB:" + d, Drive: d})
			}
		}
	}

	return devices
}

func parseUSBJSON(data string) ([]usbDevice, error) {
	type usbEntry struct {
		DeviceID     string `json:"DeviceID"`
		FriendlyName string `json:"FriendlyName"`
	}

	// Handle single vs array
	var single usbEntry
	if err := json.Unmarshal([]byte(data), &single); err == nil && single.DeviceID != "" {
		return []usbDevice{{DeviceID: single.DeviceID}}, nil
	}

	var entries []usbEntry
	if err := json.Unmarshal([]byte(data), &entries); err != nil {
		// Try splitting manually
		parts := splitJSONArray(data)
		for _, p := range parts {
			var e usbEntry
			if json.Unmarshal([]byte(p), &e) == nil && e.DeviceID != "" {
				entries = append(entries, e)
			}
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("parse error")
		}
	}

	result := make([]usbDevice, len(entries))
	for i, e := range entries {
		result[i] = usbDevice{DeviceID: e.DeviceID}
	}
	return result, nil
}

func parseDriveInfo(data string) []string {
	type driveEntry struct {
		DeviceID   string `json:"DeviceID"`
		VolumeName string `json:"VolumeName"`
	}
	var single driveEntry
	if err := json.Unmarshal([]byte(data), &single); err == nil && single.DeviceID != "" {
		return []string{single.DeviceID}
	}
	var entries []driveEntry
	if err := json.Unmarshal([]byte(data), &entries); err == nil {
		result := make([]string, len(entries))
		for i, e := range entries {
			result[i] = e.DeviceID
		}
		return result
	}
	return nil
}

func splitJSONArray(data string) []string {
	if !strings.HasPrefix(strings.TrimSpace(data), "[") {
		return nil
	}
	trimmed := strings.TrimSpace(data)
	trimmed = strings.TrimPrefix(trimmed, "[")
	trimmed = strings.TrimSuffix(trimmed, "]")

	depth := 0
	start := 0
	var parts []string
	for i, c := range trimmed {
		switch c {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				parts = append(parts, trimmed[start:i+1])
			}
		}
	}
	return parts
}

func (m *USBMonitor) emitUSBEvent(dev usbDevice, attached bool) {
	etype := EventFileCreate
	sev := SeverityInfo
	action := "attached"
	if !attached {
		etype = EventFileDelete
		action = "detached"
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      etype,
		Severity:  sev,
		File:      &FileInfo{Path: dev.DeviceID},
		Annotations: map[string]string{
			"source": "usb_monitor",
			"action": action,
			"device": dev.DeviceID,
		},
	}

	select {
	case m.eventCh <- evt:
	default:
	}
}

var _ = fmt.Sprintf
var _ = syscall.Syscall9
