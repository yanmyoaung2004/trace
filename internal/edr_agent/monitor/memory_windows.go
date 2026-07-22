//go:build windows

package monitor

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procOpenProcess       = kernel32.NewProc("OpenProcess")
	procVirtualQueryEx    = kernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	procCloseHandle       = kernel32.NewProc("CloseHandle")
)

const (
	processQueryInformation = 0x0400
	processVMRead          = 0x0010

	memCommit    = 0x1000
	memReserve   = 0x2000
	pageReadonly = 0x02
	pageReadWrite = 0x04
	pageExecuteRead = 0x20
	pageExecuteReadWrite = 0x40
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func openProcess(pid uint32) (syscall.Handle, error) {
	ret, _, err := procOpenProcess.Call(
		processQueryInformation|processVMRead,
		0,
		uintptr(pid),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenProcess: %v", err)
	}
	return syscall.Handle(ret), nil
}

func virtualQueryEx(h syscall.Handle, addr uintptr) (*memoryBasicInformation, error) {
	info := &memoryBasicInformation{}
	ret, _, _ := procVirtualQueryEx.Call(
		uintptr(h),
		addr,
		uintptr(unsafe.Pointer(info)),
		unsafe.Sizeof(*info),
	)
	if ret == 0 {
		return nil, fmt.Errorf("VirtualQueryEx at 0x%x", addr)
	}
	return info, nil
}

func readProcessMemory(h syscall.Handle, addr uintptr, size uintptr) ([]byte, error) {
	buf := make([]byte, size)
	var read uintptr
	ret, _, _ := procReadProcessMemory.Call(
		uintptr(h),
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		size,
		uintptr(unsafe.Pointer(&read)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("ReadProcessMemory at 0x%x (size %d)", addr, size)
	}
	return buf[:read], nil
}

type WindowsMemoryScanner struct {
	yara *YaraMatcher
}

func NewWindowsMemoryScanner() *WindowsMemoryScanner {
	return &WindowsMemoryScanner{yara: NewYaraMatcher()}
}

func (w *WindowsMemoryScanner) ScanProcess(pid int) ([]*MemoryFinding, error) {
	h, err := openProcess(uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer procCloseHandle.Call(uintptr(h))

	var findings []*MemoryFinding
	addr := uintptr(0)

	for {
		info, err := virtualQueryEx(h, addr)
		if err != nil {
			break
		}

		if info.State == memCommit && info.RegionSize > 0 {
			readable := info.Protect&pageReadonly != 0 ||
				info.Protect&pageReadWrite != 0 ||
				info.Protect&pageExecuteRead != 0 ||
				info.Protect&pageExecuteReadWrite != 0

			executable := info.Protect&pageExecuteRead != 0 ||
				info.Protect&pageExecuteReadWrite != 0

			if readable && info.RegionSize <= 10*1024*1024 {
				data, err := readProcessMemory(h, addr, info.RegionSize)
				if err == nil && len(data) > 0 {
					matches := w.yara.MatchBytes(data)
					for _, match := range matches {
						findings = append(findings, &MemoryFinding{
							PID:     pid,
							Region:  fmt.Sprintf("0x%x-0x%x", addr, addr+info.RegionSize),
							Size:    uint64(info.RegionSize),
							Rule:    match.Name,
							Details: match.Description,
						})
					}
				}
			}

			if executable && info.RegionSize <= 10*1024*1024 {
				data, err := readProcessMemory(h, addr, info.RegionSize)
				if err == nil && len(data) > 0 {
					matches := w.yara.MatchBytes(data)
					for _, match := range matches {
						findings = append(findings, &MemoryFinding{
							PID: pid,
							Region: fmt.Sprintf("0x%x-0x%x [EXEC]", addr, addr+info.RegionSize),
							Size:    uint64(info.RegionSize),
							Rule:    match.Name,
							Details: match.Description + " [executable region]",
						})
					}
				}
			}
		}

		if addr+info.RegionSize <= addr {
			break
		}
		addr += info.RegionSize
	}

	return findings, nil
}

func init() {
	log.Printf("[mem-scanner] Windows memory scanner initialized")
}
