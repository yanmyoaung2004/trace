//go:build windows

package monitor

import (
	"fmt"
	"log"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	authWintrust    = syscall.NewLazyDLL("wintrust.dll")
	authWinVerify   = authWintrust.NewProc("WinVerifyTrust")
	authCrypt32     = syscall.NewLazyDLL("crypt32.dll")
	authCertQuery   = authCrypt32.NewProc("CryptQueryObject")
	authCertGetName = authCrypt32.NewProc("CertGetNameStringW")
)

const (
	trustProvActionGenericVerifyV2 = 0x00000000 // WINTRUST_ACTION_GENERIC_VERIFY_V2
	wtdRevokeNone    = 0
	wtdChoiceFile    = 1
	ubChoiceFile     = 1
	certQueryObjectFile = 0x00000001
	certNameSimpleDisplay = 0x00000001
)

type winTrustFileInfo struct {
	CbStruct            uint32
	PcwszFilePath       uintptr
	HgFile              uintptr
	PgKnownSubject      uintptr
}

type winTrustData struct {
	CbStruct            uint32
	PolicyCallbackData  uintptr
	SIPCallbackData     uintptr
	UIChoice            uint32
	RevocationChecks    uint32
	UnionChoice         uint32
	FileInfo            uintptr
	StateAction         uint32
	StateData           uint32
	URLReference        uintptr
	ProvFlags           uint32
	UIContext           uint32
	ProvCallbackData    uintptr
}

type SigningStatus struct {
	Signed       bool
	Trusted      bool
	Publisher    string
	ErrorMessage string
}

func VerifySignature(filePath string) *SigningStatus {
	result := &SigningStatus{}

	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("UTF16 conversion: %v", err)
		return result
	}

	fileInfo := &winTrustFileInfo{
		CbStruct:      uint32(unsafe.Sizeof(winTrustFileInfo{})),
		PcwszFilePath: uintptr(unsafe.Pointer(pathPtr)),
	}
	_ = wtdRevokeNone

	data := &winTrustData{
		CbStruct:   uint32(unsafe.Sizeof(winTrustData{})),
		UIChoice:   2,
		UnionChoice: wtdChoiceFile,
		FileInfo:    uintptr(unsafe.Pointer(fileInfo)),
		ProvFlags:   trustProvActionGenericVerifyV2,
	}

	ret, _, _ := authWinVerify.Call(
		uintptr(unsafe.Pointer(data)),
		0, // WINTRUST_ACTION_GENERIC_VERIFY_V2
	)

	if ret == 0 {
		result.Signed = true
		result.Trusted = true
	} else if ret == 0x800B0100 {
		result.Signed = true
		result.Trusted = false
		result.ErrorMessage = "certificate not trusted"
	} else if ret == 0x800B0109 {
		result.Signed = false
		result.ErrorMessage = "certificate chain broken"
	} else if ret == 0x80096010 {
		result.Signed = true
		result.Trusted = false
		result.ErrorMessage = "signature is valid but not trusted for this action"
	} else if ret == 0x80092026 {
		result.Signed = false
		result.ErrorMessage = "file not signed"
	} else {
		result.ErrorMessage = fmt.Sprintf("WinVerifyTrust returned 0x%x", ret)
	}

	if result.Signed {
		pub := extractPublisher(filePath)
		if pub != "" {
			result.Publisher = pub
		}
	}

	return result
}

func extractPublisher(filePath string) string {
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return ""
	}

	var hStore, hMsg uintptr
	ret, _, _ := authCertQuery.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(pathPtr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		0,
	)
	if ret == 0 || hStore == 0 || hMsg == 0 {
		return ""
	}
	defer authCertQuery.Call(0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&hStore)), 0, 0)

	buf := make([]uint16, 256)
	ret, _, _ = authCertGetName.Call(
		hMsg,
		certNameSimpleDisplay,
		0,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}

	for i, c := range buf {
		if c == 0 {
			return string(utf16.Decode(buf[:i]))
		}
	}
	return string(utf16.Decode(buf))
}

var _ = log.Printf
