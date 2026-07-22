//go:build windows

package monitor

import (
	"encoding/json"
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
	phNtdll          = windows.NewLazySystemDLL("ntdll.dll")
	phNtQueryInfoProc = phNtdll.NewProc("NtQueryInformationProcess")
	phNtQueryVM      = phNtdll.NewProc("NtQueryVirtualMemory")
	phNtSuspendProc  = phNtdll.NewProc("NtSuspendProcess")
	phNtResumeProc   = phNtdll.NewProc("NtResumeProcess")
)

const (
	phProcInfoBasic     = 0
	phMemCommit         = 0x1000
	phPageRW            = 0x04
	phPageRX            = 0x20
	phPageRWX           = 0x40
	phPageGuard         = 0x100
	phProcessQueryInfo  = 0x0400
	phProcessVMRead     = 0x0010
	phProcessQueryLimit = 0x1000
)

var (
	phKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	phOpenProcess   = phKernel32.NewProc("OpenProcess")
	phCloseHandle    = phKernel32.NewProc("CloseHandle")
)

type procBasicInfo struct {
	ExitStatus       int
	PebBaseAddr      uintptr
	AffinityMask     uintptr
	BasePriority     int
	UniqueProcID     uintptr
	UniqueParentID   uintptr
}

type peb struct {
	_                [2]byte
	BeingDebugged    byte
	_                [1]byte
	_                [4]byte
	_                [4]byte
	Ldr              uintptr
	ProcessParams    uintptr
	_                [4]byte
	_                [4]byte
	_                [4]byte
	_                [4]byte
	_                [4]byte
}

type rtlUserProcessParams struct {
	_                [64]byte
	CommandLine      struct {
		Length       uint16
		MaxLength    uint16
		Buffer       uintptr
	}
	_                [8]byte
	_                [8]byte
	_                [4]byte
	_                [4]byte
	_                [4]byte
	_                [4]byte
	_                [4]byte
	_                [128]byte
}

type HollowingDetector struct {
	eventCh        chan<- *Event
	pollInterval   time.Duration
	pebSnapshots   map[int]uintptr
	mu             sync.Mutex
	done           chan struct{}
	started        bool
}

func NewHollowingDetector(eventCh chan<- *Event) *HollowingDetector {
	return &HollowingDetector{
		eventCh:      eventCh,
		pollInterval: 15 * time.Second,
		pebSnapshots: make(map[int]uintptr),
		done:         make(chan struct{}),
	}
}

func (hd *HollowingDetector) Start() error {
	hd.mu.Lock()
	if hd.started {
		hd.mu.Unlock()
		return nil
	}
	hd.started = true
	hd.mu.Unlock()

	go hd.loop()
	log.Printf("[hollowing] detector active (interval: %s)", hd.pollInterval)
	return nil
}

func (hd *HollowingDetector) Stop() {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	if hd.started {
		hd.started = false
		close(hd.done)
	}
}

func (hd *HollowingDetector) loop() {
	tick := time.NewTicker(hd.pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-hd.done:
			return
		case <-tick.C:
			hd.check()
		}
	}
}

func (hd *HollowingDetector) check() {
	procs, err := listProcesses()
	if err != nil {
		return
	}

	hd.mu.Lock()
	current := make(map[int]uintptr)

	for _, pid := range procs {
		h, err := openProc(pid)
		if err != nil {
			continue
		}

		pebAddr, err := getPebAddress(h)
		closeHandle(h)

		if err != nil {
			continue
		}
		current[pid] = pebAddr

		prevPeb, exists := hd.pebSnapshots[pid]
		if exists && prevPeb != 0 && pebAddr != 0 && prevPeb != pebAddr {
			hd.emitHollowingAlert(pid, prevPeb, pebAddr)
		}

		// Check for W^X violations
		if pebAddr != 0 {
			hd.checkWXViolations(pid)
		}
	}

	hd.pebSnapshots = current
	hd.mu.Unlock()
}

func (hd *HollowingDetector) checkWXViolations(pid int) {
	h, err := openProc(pid)
	if err != nil {
		return
	}
	defer closeHandle(h)

	addr := uintptr(0)
	const maxRegions = 1000

	for i := 0; i < maxRegions; i++ {
		var mbi struct {
			BaseAddr       uintptr
			AllocBase      uintptr
			AllocProtect   uint32
			RegionSize     uintptr
			State          uint32
			Protect        uint32
			Type           uint32
		}

		ret, _, _ := phNtQueryVM.Call(
			uintptr(h), addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi), 0,
		)
		if ret != 0 {
			break
		}
		if mbi.RegionSize == 0 {
			break
		}

		// W^X: page went from RW to RX (typical for process hollowing)
		if mbi.State == phMemCommit {
			isWX := (mbi.Protect&phPageRX != 0 || mbi.Protect&phPageRWX != 0) &&
				!(mbi.Protect&phPageGuard != 0)

			if isWX && mbi.RegionSize > 4096 {
				if mbi.AllocProtect&phPageRW != 0 {
					hd.emitWXViolation(pid, addr, mbi.RegionSize)
					break // One alert per process per scan
				}
			}
		}

		if addr+mbi.RegionSize <= addr {
			break
		}
		addr += mbi.RegionSize
	}
}

func (hd *HollowingDetector) emitHollowingAlert(pid int, oldPeb, newPeb uintptr) {
	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventAlert,
		Severity:  SeverityCritical,
		Process:   &ProcessInfo{PID: pid},
		Annotations: map[string]string{
			"source":    "hollowing_detector",
			"alert":     "peb_changed",
			"old_peb":   fmt.Sprintf("0x%x", oldPeb),
			"new_peb":   fmt.Sprintf("0x%x", newPeb),
			"detail":    "Process PEB base address changed — possible process hollowing",
		},
	}
	select {
	case hd.eventCh <- evt:
	default:
	}
}

func (hd *HollowingDetector) emitWXViolation(pid int, addr uintptr, size uintptr) {
	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventAlert,
		Severity:  SeverityCritical,
		Process:   &ProcessInfo{PID: pid},
		Annotations: map[string]string{
			"source": "hollowing_detector",
			"alert":  "wx_violation",
			"addr":   fmt.Sprintf("0x%x", addr),
			"size":   fmt.Sprintf("%d", size),
			"detail": "Memory region allocated as RW then changed to RX — possible code injection",
		},
	}
	select {
	case hd.eventCh <- evt:
	default:
	}
}

// ── PEB Command Line Capture ──

func getProcessCommandLine(pid int) (string, error) {
	h, err := openProc(pid)
	if err != nil {
		return "", err
	}
	defer closeHandle(h)

	pebAddr, err := getPebAddress(h)
	if err != nil || pebAddr == 0 {
		return "", fmt.Errorf("no peb")
	}

	var procParamsAddr uintptr
	err = readProcessMemoryH(h, pebAddr+0x20, uintptr(unsafe.Pointer(&procParamsAddr)), 8)
	if err != nil {
		return "", err
	}

	var params rtlUserProcessParams
	err = readProcessMemoryH(h, procParamsAddr, uintptr(unsafe.Pointer(&params)), unsafe.Sizeof(params))
	if err != nil {
		return "", err
	}

	if params.CommandLine.Length == 0 || params.CommandLine.Buffer == 0 {
		return "", fmt.Errorf("no cmdline")
	}

	maxLen := uint16(4096)
	if params.CommandLine.Length > maxLen {
		params.CommandLine.Length = maxLen
	}

	buf := make([]uint16, params.CommandLine.Length/2)
	err = readProcessMemoryH(h, params.CommandLine.Buffer, uintptr(unsafe.Pointer(&buf[0])), uintptr(params.CommandLine.Length))
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(buf), nil
}

// ── Helpers ──

func openProc(pid int) (syscall.Handle, error) {
	ret, _, _ := phOpenProcess.Call(
		phProcessQueryInfo|phProcessVMRead|phProcessQueryLimit,
		0, uintptr(pid),
	)
	if ret == 0 {
		return 0, fmt.Errorf("openproc(%d) failed", pid)
	}
	return syscall.Handle(ret), nil
}

func closeHandle(h syscall.Handle) {
	phCloseHandle.Call(uintptr(h))
}

func getPebAddress(h syscall.Handle) (uintptr, error) {
	var info procBasicInfo
	var retLen uint32
	ret, _, _ := phNtQueryInfoProc.Call(
		uintptr(h), phProcInfoBasic,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("NtQueryInfoProcess: 0x%x", ret)
	}
	return info.PebBaseAddr, nil
}

func listProcesses() ([]int, error) {
	var pids []int
	data, err := runCmd("powershell", "-NoProfile", "-Command",
		"Get-Process | Select-Object -ExpandProperty Id | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}

	var single int
	if err := json.Unmarshal([]byte(data), &single); err == nil {
		return []int{single}, nil
	}

	if err := json.Unmarshal([]byte(data), &pids); err == nil {
		return pids, nil
	}

	return nil, fmt.Errorf("parse error")
}

func readProcessMemoryH(h syscall.Handle, addr, buf uintptr, size uintptr) error {
	var read uintptr
	ret, _, _ := memReadProcessMemory.Call(
		uintptr(h), addr, buf, size,
		uintptr(unsafe.Pointer(&read)),
	)
	if ret == 0 {
		return fmt.Errorf("readprocessmemory 0x%x failed", addr)
	}
	return nil
}

var hollowingDropped int64
var _ = atomic.LoadInt64
