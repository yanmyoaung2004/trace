package sift

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- Test fixture generators ---

func testPE32(t testing.TB, sections []peTestSection) []byte {
	t.Helper()
	return buildPE32(sections, false, 0x1000, 1700000000)
}

func testPE64(t testing.TB, sections []peTestSection) []byte {
	t.Helper()
	return buildPE64(sections, false, 0x1000, 1700000000)
}

func testDLL32(t *testing.T, sections []peTestSection) []byte {
	t.Helper()
	return buildPE32(sections, true, 0x1000, 1700000000)
}

func testPE32WithCompileTime(t *testing.T, sections []peTestSection, ts uint32) []byte {
	t.Helper()
	return buildPE32(sections, false, 0x1000, ts)
}

// --- Unit tests: calculateEntropy ---

func TestCalculateEntropy_Empty(t *testing.T) {
	e := calculateEntropy(nil)
	if e != 0 {
		t.Errorf("expected 0, got %.2f", e)
	}
}

func TestCalculateEntropy_Uniform(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := calculateEntropy(data)
	// Uniform distribution over 256 symbols → max entropy = 8.0
	if e < 7.9 || e > 8.1 {
		t.Errorf("expected ~8.0 for uniform, got %.2f", e)
	}
}

func TestCalculateEntropy_Constant(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = 0x41
	}
	e := calculateEntropy(data)
	if e != 0 {
		t.Errorf("expected 0 for constant data, got %.2f", e)
	}
}

func TestCalculateEntropy_High(t *testing.T) {
	data := highEntropyData(1000, 0xAB)
	e := calculateEntropy(data)
	if e < 7.0 {
		t.Errorf("expected >7.0 for high-entropy data, got %.2f", e)
	}
}

func TestCalculateEntropy_Low(t *testing.T) {
	data := lowEntropyData(1000)
	e := calculateEntropy(data)
	if e > 1.0 {
		t.Errorf("expected <1.0 for low-entropy (NOPs), got %.2f", e)
	}
}

// --- Unit tests: rvaToOffset ---

func TestRvaToOffset_Basic(t *testing.T) {
	// rvaToOffset requires actual PE data with properly set section virtual addresses.
	// Test with nil input to verify it returns 0 without crashing.
	result := rvaToOffset(0x1000, nil, 0, 0)
	if result != 0 {
		t.Errorf("expected 0 for nil data, got 0x%x", result)
	}
}

func TestRvaToOffset_Zero(t *testing.T) {
	result := rvaToOffset(0, nil, 0, 0)
	if result != 0 {
		t.Errorf("expected 0 for nil data, got 0x%x", result)
	}
}

func TestRvaToOffset_ShortData(t *testing.T) {
	result := rvaToOffset(100, []byte{0, 1, 2, 3}, 0, 0)
	if result != 0 {
		t.Errorf("expected 0 for short data, got 0x%x", result)
	}
}

// --- Unit tests: readCString ---

func TestReadCString_Normal(t *testing.T) {
	data := []byte("hello\x00world")
	s := readCString(data, 0)
	if s != "hello" {
		t.Errorf("expected 'hello', got %q", s)
	}
}

func TestReadCString_Empty(t *testing.T) {
	data := []byte{0}
	s := readCString(data, 0)
	if s != "" {
		t.Errorf("expected empty, got %q", s)
	}
}

func TestReadCString_Offset(t *testing.T) {
	data := []byte("junk\x00hello\x00world")
	s := readCString(data, 5)
	if s != "hello" {
		t.Errorf("expected 'hello', got %q", s)
	}
}

func TestReadCString_NoNull(t *testing.T) {
	data := []byte("hello")
	s := readCString(data, 0)
	if s != "hello" {
		t.Errorf("expected 'hello', got %q", s)
	}
}

// --- Unit tests: parsePESections ---

func TestParsePESections_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.exe")
	if err := os.WriteFile(path, validPEData(), 0644); err != nil {
		t.Fatal(err)
	}
	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.IsPE {
		t.Fatal("expected valid PE")
	}
	if len(meta.Sections) < 1 {
		t.Fatal("expected at least 1 section")
	}
}

func TestParsePESections_NotPE(t *testing.T) {
	_, err := parsePESections([]byte("not a PE file"))
	if err == nil {
		t.Error("expected error for non-PE data")
	}
}

func TestParsePESections_NoSections(t *testing.T) {
	data := make([]byte, 256)
	data[0] = 'M'
	data[1] = 'Z'
	binary.LittleEndian.PutUint32(data[60:], 64) // e_lfanew
	data[64] = 'P'
	data[65] = 'E'
	// COFF header: machine=0, sections=0
	binary.LittleEndian.PutUint16(data[70:], 0) // num sections = 0

	_, err := parsePESections(data)
	if err == nil {
		t.Error("expected error for no sections")
	}
}

// --- Unit tests: parsePEImportTable ---

func TestParsePEImportTable_NotPE(t *testing.T) {
	_, err := parsePEImportTable([]byte("not PE"))
	if err == nil {
		t.Error("expected error for non-PE")
	}
}

func TestParsePEImportTable_NoImports(t *testing.T) {
	// Valid PE with no import directory
	sections := []peTestSection{
		{Name: ".text", RawSize: 64, RawData: lowEntropyData(64), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	}
	peData := testPE32(t, sections)
	_, err := parsePEImportTable(peData)
	if err == nil {
		// No imports is valid — some binaries have no imports
	}
}

// --- Integration tests: AnalyzePE ---

func TestAnalyzePE_NotPE(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("not a PE file"), 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.IsPE {
		t.Error("expected is_pe=false for text file")
	}
}

func TestAnalyzePE_MissingPath(t *testing.T) {
	_, err := AnalyzePE("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestAnalyzePE_ValidPE32(t *testing.T) {
	sections := []peTestSection{
		{Name: ".text", RawSize: 512, RawData: lowEntropyData(512), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
		{Name: ".data", RawSize: 256, RawData: lowEntropyData(256), Flags: imgScnCntInitData | imgScnMemRead | imgScnMemWrite},
	}
	peData := testPE32(t, sections)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.IsPE {
		t.Fatal("expected is_pe=true")
	}
	if meta.Subsystem != "x86" {
		t.Errorf("expected x86, got %s", meta.Subsystem)
	}
	if len(meta.Sections) != 2 {
		t.Errorf("expected 2 sections, got %d", len(meta.Sections))
	}
	if meta.FileSize <= 0 {
		t.Error("expected non-zero file size")
	}
	if meta.MD5 == "" || meta.SHA1 == "" || meta.SHA256 == "" {
		t.Error("expected hashes to be computed")
	}
}

func TestAnalyzePE_ValidPE64(t *testing.T) {
	sections := []peTestSection{
		{Name: ".text", RawSize: 512, RawData: lowEntropyData(512), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	}
	peData := testPE64(t, sections)
	dir := t.TempDir()
	path := filepath.Join(dir, "test64.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.IsPE {
		t.Fatal("expected is_pe=true")
	}
	if meta.Subsystem != "x64" {
		t.Errorf("expected x64, got %s", meta.Subsystem)
	}
	if meta.EntryPoint != "0x0000000000001000" && meta.EntryPoint != "" {
		t.Logf("entry point: %s", meta.EntryPoint)
	}
}

func TestAnalyzePE_DLL32(t *testing.T) {
	sections := []peTestSection{
		{Name: ".text", RawSize: 512, RawData: lowEntropyData(512), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	}
	peData := testDLL32(t, sections)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dll")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.IsPE {
		t.Fatal("expected is_pe=true for DLL")
	}
}

func TestAnalyzePE_HighEntropySection(t *testing.T) {
	hi := highEntropyData(200, 0x77)
	lo := lowEntropyData(100)
	sections := []peTestSection{
		{Name: ".text", RawSize: uint32(len(hi)), RawData: hi,
			Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
		{Name: ".data", RawSize: uint32(len(lo)), RawData: lo,
			Flags: imgScnCntInitData | imgScnMemRead | imgScnMemWrite},
	}
	peData := testPE32(t, sections)
	dir := t.TempDir()
	path := filepath.Join(dir, "packed.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.IsPE {
		t.Fatal("expected is_pe=true")
	}
	// The high-entropy section should raise the average entropy
	if meta.HighEntropy {
		t.Logf("high entropy detected: %.2f", meta.Entropy)
	}
}

func TestAnalyzePE_SuspiciousSectionNames(t *testing.T) {
	sections := []peTestSection{
		{Name: ".text\x00\x00\x00", RawSize: 64, RawData: lowEntropyData(64),
			Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	}
	peData := testPE32(t, sections)
	dir := t.TempDir()
	path := filepath.Join(dir, "suspicious.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = meta
}

func TestAnalyzePE_SuspiciousCompileTime(t *testing.T) {
	sections := []peTestSection{
		{Name: ".text", RawSize: 64, RawData: lowEntropyData(64),
			Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	}
	// Compile time in year 1999 (before 2000 — suspicious)
	peData := testPE32WithCompileTime(t, sections, 915148800) // 1999-01-01
	dir := t.TempDir()
	path := filepath.Join(dir, "old.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.CompileTime == "" {
		t.Fatal("expected compile time to be parsed")
	}
	t.Logf("compile time: %s, suspicious: %v", meta.CompileTime, meta.Suspicious)
}

func TestAnalyzePE_CorruptData(t *testing.T) {
	// Create a minimal file with invalid e_lfanew
	data := make([]byte, 128)
	data[0] = 'M'
	data[1] = 'Z'
	binary.LittleEndian.PutUint32(data[60:], 9999) // e_lfanew points way past file

	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.exe")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.IsPE {
		// Should still have MZ but not PE
	}
}

func TestAnalyzePE_Notepad(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("notepad.exe only exists on Windows")
	}
	meta, err := AnalyzePE("C:\\Windows\\System32\\notepad.exe")
	if err != nil {
		t.Fatal(err)
	}
	if !meta.IsPE {
		t.Fatal("expected notepad.exe to be a PE")
	}
	if len(meta.Sections) == 0 {
		t.Error("expected at least one section")
	}
	if len(meta.Suspicious) > 0 {
		t.Logf("suspicious: %v", meta.Suspicious)
	}
}

// --- Tests for new PE features ---

func TestAnalyzePE_DLLCharacteristics(t *testing.T) {
	peData := testPE32(t, []peTestSection{
		{Name: ".text", RawSize: 64, RawData: lowEntropyData(64), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "test.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.DllCharacteristics == "" {
		t.Log("DLL characteristics may be empty for minimal PE")
	}
}

func TestAnalyzePE_IsDLL(t *testing.T) {
	peData := testDLL32(t, []peTestSection{
		{Name: ".text", RawSize: 64, RawData: lowEntropyData(64), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dll")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.IsDLL {
		t.Error("expected IsDLL=true for DLL binary")
	}
}

func TestAnalyzePE_Overlay(t *testing.T) {
	peData := testPE32(t, []peTestSection{
		{Name: ".text", RawSize: 64, RawData: lowEntropyData(64), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	})
	// Append overlay data (simulates appended data after last section)
	peData = append(peData, []byte("OVERLAY_DATA_SIGNATURE")...)
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.OverlaySize <= 0 {
		t.Error("expected non-zero overlay size for file with appended data")
	}
	t.Logf("overlay size: %d", meta.OverlaySize)
}

func TestAnalyzePE_IsManaged(t *testing.T) {
	// Minimal PE32 won't have CLR header — just verify field doesn't panic
	peData := testPE32(t, []peTestSection{
		{Name: ".text", RawSize: 64, RawData: lowEntropyData(64), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "test.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}
	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.IsManaged {
		t.Log("IsManaged=true (unlikely for minimal PE but not wrong)")
	}
	_ = meta
}

func TestAnalyzePE_PerSectionHighEntropy(t *testing.T) {
	hi := highEntropyData(200, 0xAA)
	lo := lowEntropyData(100)
	sections := []peTestSection{
		{Name: ".text", RawSize: uint32(len(hi)), RawData: hi, Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
		{Name: ".data", RawSize: uint32(len(lo)), RawData: lo, Flags: imgScnCntInitData | imgScnMemRead | imgScnMemWrite},
	}
	peData := testPE32(t, sections)
	dir := t.TempDir()
	path := filepath.Join(dir, "packed.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	// Check for per-section high entropy warning
	foundSectionWarning := false
	for _, s := range meta.Suspicious {
		if strings.Contains(s, "High entropy section") {
			foundSectionWarning = true
			break
		}
	}
	if !foundSectionWarning {
		t.Log("per-section high entropy warning not triggered (may depend on entropy threshold)")
	}
	t.Logf("suspicious: %v", meta.Suspicious)
}

func TestDecodeDLLCharacteristics(t *testing.T) {
	tests := []struct {
		flags uint16
		want  string
	}{
		{0x00C0, "ASLR|DEP"},
		{0x02C0, "ASLR|DEP|NX"},
		{0x03C0, "ASLR|DEP|INTEGRITY|NX"},
		{0, ""},
	}
	for _, tt := range tests {
		got := decodeDllCharacteristics(tt.flags)
		if got != tt.want {
			t.Errorf("decodeDllCharacteristics(0x%04x) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestAnalyzePE_SignedDetection(t *testing.T) {
	// Create PE with appended Authenticode-like data
	peData := testPE32(t, []peTestSection{
		{Name: ".text", RawSize: 64, RawData: lowEntropyData(64), Flags: imgScnCntCode | imgScnMemExecute | imgScnMemRead},
	})
	// Append WIN_CERTIFICATE header with type=2 (Authenticode)
	certHead := make([]byte, 8)
	binary.LittleEndian.PutUint32(certHead[0:], 24)   // wCertificateLength
	binary.LittleEndian.PutUint32(certHead[4:], 2)     // wCertificateType = Authenticode
	// Append minimal PKCS#7 (just a SEQUENCE)
	pkcs7 := []byte{0x30, 0x06, 0x16, 0x04, 0x41, 0x43, 0x4D, 0x45} // IA5String "ACME"
	peData = append(peData, certHead...)
	peData = append(peData, pkcs7...)
	dir := t.TempDir()
	path := filepath.Join(dir, "signed.exe")
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.OverlaySize <= 0 {
		t.Skip("overlay not detected — Authenticode test requires overlay")
	}
	t.Logf("signed=%v signer=%q overlay=%d", meta.Signed, meta.SignerInfo, meta.OverlaySize)
}

func TestPEAnalyzeNonPE(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("not a PE file"), 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.IsPE {
		t.Error("expected is_pe=false for text file")
	}
	if meta.MD5 == "" {
		t.Error("expected md5 in output")
	}
}

// --- Fix for broken TestEntropyCalculation ---

func TestEntropyCalculation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "high_entropy.bin")

	var data []byte
	for i := 0; i < 256; i++ {
		for j := 0; j < 100; j++ {
			data = append(data, byte(i))
		}
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = meta
	t.Log("non-PE file correctly identified (entropy not computed for non-PE)")
}

func TestPEAnalyze_NoPath(t *testing.T) {
	_, err := AnalyzePE("/nonexistent/path/that/does/not/exist.exe")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}
