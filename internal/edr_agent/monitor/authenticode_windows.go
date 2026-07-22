//go:build windows

package monitor

import (
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	authWintrust  = syscall.NewLazyDLL("wintrust.dll")
	authVerify    = authWintrust.NewProc("WinVerifyTrust")
	authCrypt32   = syscall.NewLazyDLL("crypt32.dll")
	authQueryObj  = authCrypt32.NewProc("CryptQueryObject")
	authCertName  = authCrypt32.NewProc("CertGetNameStringW")
	authFree      = authCrypt32.NewProc("CertFreeCertificateContext")
)

const (
	certQueryObjectFile = 0x1
	certNameSimpleDisplay = 0x1
)

type winTrustFileInfo struct {
	CbStruct      uint32
	PcwszFilePath uintptr
	HgFile        uintptr
	PgKnownSubject uintptr
}

type winTrustData struct {
	CbStruct           uint32
	PolicyCallbackData uintptr
	SIPCallbackData    uintptr
	UIChoice           uint32
	RevocationChecks   uint32
	UnionChoice        uint32
	FileInfo           uintptr
	StateAction        uint32
	StateData          uint32
	URLReference       uintptr
	ProvFlags          uint32
	UIContext          uint32
	ProvCallbackData   uintptr
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
		result.ErrorMessage = fmt.Sprintf("UTF16: %v", err)
		return result
	}

	fileInfo := &winTrustFileInfo{
		CbStruct:      uint32(unsafe.Sizeof(winTrustFileInfo{})),
		PcwszFilePath: uintptr(unsafe.Pointer(pathPtr)),
	}

	data := &winTrustData{
		CbStruct:   uint32(unsafe.Sizeof(winTrustData{})),
		UIChoice:   2,
		UnionChoice: 1,
		FileInfo:    uintptr(unsafe.Pointer(fileInfo)),
	}

	ret, _, _ := authVerify.Call(uintptr(unsafe.Pointer(data)), 0)
	decodeVerifyResult(ret, result)

	if result.Signed {
		result.Publisher = extractPublisherFromFile(filePath)
	}
	return result
}

func decodeVerifyResult(ret uintptr, result *SigningStatus) {
	switch {
	case ret == 0:
		result.Signed = true
		result.Trusted = true
	case ret == 0x800B0100:
		result.Signed = true
		result.ErrorMessage = "not trusted (root CA not in store)"
	case ret == 0x800B0109:
		result.ErrorMessage = "cert chain broken"
	case ret == 0x80096010:
		result.Signed = true
		result.ErrorMessage = "not trusted for this action"
	case ret == 0x80092026:
		result.ErrorMessage = "not signed"
	default:
		result.ErrorMessage = fmt.Sprintf("WinVerifyTrust: 0x%x", ret)
	}
}

func extractPublisherFromFile(filePath string) string {
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return ""
	}

	var dwEncoding, dwContentType, dwFormatType uint32
	var hStore uintptr
	var hMsg uintptr
	var pvContext uintptr

	ret, _, _ := authQueryObj.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&dwEncoding)),
		uintptr(unsafe.Pointer(&dwContentType)),
		uintptr(unsafe.Pointer(&dwFormatType)),
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		uintptr(unsafe.Pointer(&pvContext)),
	)
	if ret != 0 || pvContext == 0 {
		return ""
	}
	defer authFree.Call(pvContext)

	buf := make([]uint16, 256)
	ret, _, _ = authCertName.Call(
		pvContext,
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
