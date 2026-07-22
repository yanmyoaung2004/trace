//go:build windows

package monitor

import (
	"fmt"
	"log"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	memKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	memNtdll    = windows.NewLazySystemDLL("ntdll.dll")

	memOpenProcess       = memKernel32.NewProc("OpenProcess")
	memVirtualQueryEx    = memKernel32.NewProc("VirtualQueryEx")
	memReadProcessMemory = memKernel32.NewProc("ReadProcessMemory")
	memCloseHandle       = memKernel32.NewProc("CloseHandle")
	memNtQueryInfoProcess = memNtdll.NewProc("NtQueryInformationProcess")
)

const (
	memProcessQueryInfo = 0x0400
	memProcessVMRead    = 0x0010
	memProcessQueryLimited = 0x1000

	memCommit         = 0x1000
	memPageReadonly   = 0x02
	memPageReadWrite  = 0x04
	memPageExecuteRead = 0x20
	memPageExecReadWrite = 0x40
	memPageGuard       = 0x100
	memPageNoAccess    = 0x01

	processProtectionInfo = 0x3D
	protectLevelWinTrusted = 1
	protectLevelWinSystem  = 2
	protectLevelWinTCB     = 3
)

type memBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type processProtection struct {
	Level uint8
	_     [3]byte
	Type  uint8
	_     [3]byte
	_     [8]byte
}

type WindowsMemScanner struct {
	yara   *YaraMatcher
	mu     sync.Mutex
	pplWarned map[int]bool
}

func NewWindowsMemScanner() *WindowsMemScanner {
	return &WindowsMemScanner{
		yara:     NewYaraMatcher(),
		pplWarned: make(map[int]bool),
	}
}

func (w *WindowsMemScanner) ScanProcess(pid int) ([]*MemoryFinding, error) {
	if w.isPPL(pid) {
		w.mu.Lock()
		if !w.pplWarned[pid] {
			w.pplWarned[pid] = true
			w.mu.Unlock()
			log.Printf("[mem-scan] PID %d is PPL-protected, skipping", pid)
		} else {
			w.mu.Unlock()
		}
		return nil, nil
	}

	h, err := w.openProcess(pid)
	if err != nil {
		return nil, err
	}
	defer memCloseHandle.Call(uintptr(h))

	var findings []*MemoryFinding
	addr := uintptr(0)

	for {
		var info memBasicInfo
		ret, _, _ := memVirtualQueryEx.Call(
			uintptr(h), addr,
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
		)
		if ret == 0 {
			break
		}
		if info.RegionSize == 0 {
			break
		}

		if info.State == memCommit && info.RegionSize > 0 && info.RegionSize <= 10*1024*1024 {
			if info.Protect&memPageGuard != 0 || info.Protect&memPageNoAccess != 0 {
				addr += info.RegionSize
				continue
			}

			readable := info.Protect&memPageReadonly != 0 ||
				info.Protect&memPageReadWrite != 0 ||
				info.Protect&memPageExecuteRead != 0 ||
				info.Protect&memPageExecReadWrite != 0
			executable := info.Protect&memPageExecuteRead != 0 ||
				info.Protect&memPageExecReadWrite != 0

			if readable || executable {
				findings = w.scanRegion(h, pid, addr, info, readable, executable, findings)
			}
		}

		if addr+info.RegionSize <= addr {
			break
		}
		addr += info.RegionSize
	}

	return findings, nil
}

func (w *WindowsMemScanner) scanRegion(h syscall.Handle, pid int, addr uintptr, info memBasicInfo, readable, executable bool, findings []*MemoryFinding) []*MemoryFinding {
	done := make(chan struct{}, 1)
	var data []byte
	var readErr error

	go func() {
		buf := make([]byte, info.RegionSize)
		var read uintptr
		ret, _, _ := memReadProcessMemory.Call(
			uintptr(h), addr,
			uintptr(unsafe.Pointer(&buf[0])),
			info.RegionSize,
			uintptr(unsafe.Pointer(&read)),
		)
		if ret != 0 && read > 0 {
			data = buf[:read]
		} else {
			readErr = fmt.Errorf("read failed")
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		log.Printf("[mem-scan] timeout reading 0x%x (size %d) on PID %d", addr, info.RegionSize, pid)
		return findings
	}

	if readErr != nil || len(data) == 0 {
		return findings
	}

	matches := w.yara.MatchBytes(data)
	for _, match := range matches {
		tag := ""
		if executable {
			tag = " [EXEC]"
		}
		findings = append(findings, &MemoryFinding{
			PID:     pid,
			Region:  fmt.Sprintf("0x%x-0x%x%s", addr, addr+info.RegionSize, tag),
			Size:    uint64(info.RegionSize),
			Rule:    match.Name,
			Details: match.Description,
		})
	}
	return findings
}

func (w *WindowsMemScanner) openProcess(pid int) (syscall.Handle, error) {
	ret, _, _ := memOpenProcess.Call(
		memProcessQueryInfo|memProcessVMRead|memProcessQueryLimited,
		0, uintptr(pid),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenProcess(%d) failed", pid)
	}
	return syscall.Handle(ret), nil
}

func (w *WindowsMemScanner) isPPL(pid int) bool {
	h, err := w.openProcess(pid)
	if err != nil {
		return false
	}
	defer memCloseHandle.Call(uintptr(h))

	var prot processProtection
	var retLen uint32
	ret, _, _ := memNtQueryInfoProcess.Call(
		uintptr(h), processProtectionInfo,
		uintptr(unsafe.Pointer(&prot)), unsafe.Sizeof(prot),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ret != 0 {
		return false
	}
	return prot.Level >= protectLevelWinTrusted
}

func init() {
	log.Printf("[mem-scanner] Windows memory scanner active")
}
