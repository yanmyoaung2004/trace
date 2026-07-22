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
	usbUser32    = windows.NewLazySystemDLL("user32.dll")
	usbRegDevNot = usbUser32.NewProc("RegisterDeviceNotificationW")
	usbUnRegDevN = usbUser32.NewProc("UnregisterDeviceNotification")
	usbGetDriveT = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDriveTypeW")
)

const devNotifyDeviceInterface = 0x00000005
const devNotifyAllInterface = 0x00000004

type USBMonitor struct {
	eventCh     chan<- *Event
	notifHandle uintptr
	mu          sync.Mutex
	started     bool
	done        chan struct{}
	knownDrives map[string]bool
}

func NewUSBMonitor(eventCh chan<- *Event) *USBMonitor {
	return &USBMonitor{
		eventCh:     eventCh,
		done:        make(chan struct{}),
		knownDrives: make(map[string]bool),
	}
}

func (m *USBMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}

	// Try RegisterDeviceNotification (requires window handle — console apps
	// can use HWND_BROADCAST). If it fails, fall back to polling.
	dbcc := make([]byte, 32)
	copy(dbcc, packU32(32))
	copy(dbcc[4:8], packU32(devNotifyDeviceInterface))
	// GUID_DEVINTERFACE_USB_DEVICE
	usbGuid := [16]byte{0x10, 0xBF, 0xDC, 0xA5, 0x30, 0x65, 0xD2, 0x11,
		0x90, 0x1A, 0x00, 0xC0, 0x4F, 0xB9, 0x49, 0x5E}
	copy(dbcc[12:28], usbGuid[:])

	// Use 0xFFFF (HWND_BROADCAST) as fallback handle
	ret, _, _ := usbRegDevNot.Call(0xFFFF,
		uintptr(unsafe.Pointer(&dbcc[0])),
		devNotifyAllInterface)

	if ret != 0 {
		m.notifHandle = ret
		log.Printf("[usb] RegisterDeviceNotification active")
	} else {
		log.Printf("[usb] RegisterDeviceNotification unavailable — polling every 15s")
	}

	m.started = true
	m.syncDrives()
	go m.monitorLoop()
	return nil
}

func (m *USBMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		m.started = false
		close(m.done)
		if m.notifHandle != 0 {
			usbUnRegDevN.Call(m.notifHandle)
		}
	}
}

func (m *USBMonitor) monitorLoop() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-tick.C:
			m.syncDrives()
		}
	}
}

func (m *USBMonitor) syncDrives() {
	current := make(map[string]bool)
	for _, d := range enumDrives() {
		if getDriveType(d) == 2 { // DRIVE_REMOVABLE
			current[d] = true
			if !m.knownDrives[d] {
				m.knownDrives[d] = true
				m.emitUSBEvent(d, true)
			}
		}
	}
	for d := range m.knownDrives {
		if !current[d] {
			delete(m.knownDrives, d)
			m.emitUSBEvent(d, false)
		}
	}
}

func enumDrives() []string {
	var drives []string
	buf := make([]uint16, 256)
	n, _ := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if n == 0 {
		return nil
	}
	for i := 0; i < len(buf) && buf[i] != 0; {
		j := i
		for j < len(buf) && buf[j] != 0 {
			j++
		}
		drive := windows.UTF16ToString(buf[i:j])
		if len(drive) >= 2 && drive[1] == ':' {
			drives = append(drives, drive[:2])
		}
		i = j + 1
	}
	return drives
}

func getDriveType(drive string) uint32 {
	path, _ := syscall.UTF16PtrFromString(drive + "\\")
	ret, _, _ := usbGetDriveT.Call(uintptr(unsafe.Pointer(path)))
	return uint32(ret)
}

func (m *USBMonitor) emitUSBEvent(drive string, attached bool) {
	action := "attached"
	if !attached {
		action = "detached"
	}
	evt := &Event{
		ID: uuid.New().String(), Timestamp: time.Now(),
		Type: EventFileCreate, Severity: SeverityInfo,
		File: &FileInfo{Path: drive + "\\"},
		Annotations: map[string]string{
			"source": "usb", "action": action, "device": drive,
		},
	}
	select {
	case m.eventCh <- evt:
	default:
	}
}

func packU32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

var _ = fmt.Sprintf
