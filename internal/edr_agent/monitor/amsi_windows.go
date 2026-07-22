//go:build windows

package monitor

import (
	"log"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	amsiDll        syscall.Handle
	amsiOpen       uintptr
	amsiScanBuf    uintptr
	amsiScanStr    uintptr
	amsiClose      uintptr
	amsiInit       uintptr
	amsiMu         sync.Mutex
	amsiInitialized bool
	amsiAvailable  bool
)

const (
	amsiResultClean      = 0
	amsiResultNotDetected = 1
	amsiResultBlockedByPolicy = 2
	amsiResultDetected   = 32768
)

type amsiContext struct {
	_ [64]byte
}

func initAMSI() {
	amsiMu.Lock()
	defer amsiMu.Unlock()
	if amsiInitialized {
		return
	}
	amsiInitialized = true

	dll, err := syscall.LoadLibrary("amsi.dll")
	if err != nil {
		log.Printf("[amsi] not available: %v", err)
		return
	}
	amsiDll = dll

	amsiOpen = getProcAddr(dll, "AmsiInitialize")
	amsiScanBuf = getProcAddr(dll, "AmsiScanBuffer")
	amsiScanStr = getProcAddr(dll, "AmsiScanString")
	amsiClose = getProcAddr(dll, "AmsiUninitialize")
	amsiInit = getProcAddr(dll, "AmsiInitialize")

	if amsiScanBuf == 0 && amsiScanStr == 0 {
		log.Printf("[amsi] neither AmsiScanBuffer nor AmsiScanString found")
		syscall.FreeLibrary(dll)
		return
	}

	amsiAvailable = true
	log.Printf("[amsi] initialized (scan=%s)",
		map[bool]string{true: "buffer", false: "string"}[amsiScanBuf != 0])
}

func getProcAddr(dll syscall.Handle, name string) uintptr {
	addr, err := syscall.GetProcAddress(dll, name)
	if err != nil {
		return 0
	}
	return addr
}

var amsiLastResult int32

func scanAMSI(content []byte, contentKind string) bool {
	if !amsiAvailable || len(content) == 0 {
		return false
	}

	amsiMu.Lock()
	ctx := &amsiContext{}
	ret, _, _ := syscall.SyscallN(amsiOpen,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("TraceAgent"))),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret != 0 {
		amsiMu.Unlock()
		log.Printf("[amsi] AmsiInitialize failed: 0x%x", ret)
		return false
	}

	scanFn := amsiScanBuf
	if scanFn == 0 {
		scanFn = amsiScanStr
	}

	var result int32
	if amsiScanBuf != 0 {
		syscall.SyscallN(scanFn,
			uintptr(unsafe.Pointer(ctx)),
			uintptr(unsafe.Pointer(&content[0])),
			uintptr(uint32(len(content))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(contentKind))),
			0,
			uintptr(unsafe.Pointer(&result)),
		)
	} else {
		syscall.SyscallN(scanFn,
			uintptr(unsafe.Pointer(ctx)),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(string(content)))),
			0,
			uintptr(unsafe.Pointer(&result)),
		)
	}

	syscall.SyscallN(amsiClose, uintptr(unsafe.Pointer(ctx)))
	amsiMu.Unlock()

	atomic.StoreInt32(&amsiLastResult, result)
	return result >= amsiResultDetected
}

func ScanBufferWithAMSI(content []byte, context string) bool {
	if !amsiAvailable {
		return false
	}
	return scanAMSI(content, context)
}

func AmsiLastResult() int32 {
	return atomic.LoadInt32(&amsiLastResult)
}

var _ = amsiInit
