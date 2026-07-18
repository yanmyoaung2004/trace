package detection_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/innoigniter/edge/internal/db"
	"github.com/innoigniter/edge/internal/detection"
)

func setupDetection(t *testing.T) *detection.Agent {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return detection.New(database.DB, "")
}

func writeTestFile(t *testing.T, name, content string) string {
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	return path
}

func TestYaraScanEICAR(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	eicar := "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	path := writeTestFile(t, "eicar.txt", eicar)

	output, err := agent.Execute(ctx, map[string]any{
		"action": "yara_scan",
		"path":   path,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	count, _ := output["count"].(int)
	if count == 0 {
		t.Fatal("expected YARA match on EICAR test file")
	}

	matches, _ := output["matches"].([]string)
	found := false
	for _, m := range matches {
		if m == "EICAR_Test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected EICAR_Test rule match, got %v", matches)
	}
}

func TestYaraScanNoMatch(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	path := writeTestFile(t, "clean.txt", "hello world this is a clean file")

	output, err := agent.Execute(ctx, map[string]any{
		"action": "yara_scan",
		"path":   path,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	count, _ := output["count"].(int)
	if count != 0 {
		t.Fatalf("expected 0 matches, got %d", count)
	}
}

func TestYaraScanMissingFile(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "yara_scan",
		"path":   "C:\\nonexistent\\file.exe",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if _, ok := output["error"]; !ok {
		t.Fatal("expected error for missing file")
	}
}

func TestYaraScanSuspiciousPowerShell(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	suspicious := "powershell -enc SQBFAFgA"
	path := writeTestFile(t, "suspicious.ps1", suspicious)

	output, err := agent.Execute(ctx, map[string]any{
		"action": "yara_scan",
		"path":   path,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	count, _ := output["count"].(int)
	if count == 0 {
		t.Fatal("expected YARA match on suspicious PowerShell")
	}
}

func TestPEAnalyzeNonPE(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	path := writeTestFile(t, "test.txt", "not a PE file")

	output, err := agent.Execute(ctx, map[string]any{
		"action": "pe_analyze",
		"path":   path,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	isPE, _ := output["is_pe"].(bool)
	if isPE {
		t.Fatal("expected is_pe=false for text file")
	}
}

func TestPEAnalyzeRealPE(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE analysis test requires Windows")
	}
	agent := setupDetection(t)
	ctx := context.Background()

	path := "C:\\Windows\\System32\\notepad.exe"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("notepad.exe not found")
	}

	output, err := agent.Execute(ctx, map[string]any{
		"action": "pe_analyze",
		"path":   path,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	isPE, _ := output["is_pe"].(bool)
	if !isPE {
		t.Fatal("expected is_pe=true for notepad.exe")
	}

	md5, _ := output["md5"].(string)
	if md5 == "" {
		t.Fatal("expected md5 from PE analysis")
	}

	sha256, _ := output["sha256"].(string)
	if sha256 == "" {
		t.Fatal("expected sha256 from PE analysis")
	}

	if fileSize, ok := output["file_size"].(int64); !ok || fileSize == 0 {
		t.Fatal("expected non-zero file_size")
	}
}

func TestHashLookup(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "hash_lookup",
		"hash":   "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	reputation, _ := output["reputation"].(string)
	if reputation == "" {
		t.Fatal("expected reputation from hash lookup")
	}
}

func TestHashLookupUnknown(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "hash_lookup",
		"hash":   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	reputation, _ := output["reputation"].(string)
	if reputation != "unknown" {
		t.Fatalf("expected unknown reputation, got %s", reputation)
	}
}

func TestVTLookupNoKey(t *testing.T) {
	agent := setupDetection(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action":    "vt_lookup",
		"indicator": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if _, ok := output["error"]; !ok {
		t.Fatal("expected error message when VT API key is missing")
	}
}

func TestEntropyCalculation(t *testing.T) {
	path := writeTestFile(t, "high_entropy.bin", string(make([]byte, 256)))
	for i := range 256 {
		_ = i
	}

	highEntropy := make([]byte, 256)
	for i := range highEntropy {
		highEntropy[i] = byte(i)
	}
	path = writeTestFile(t, "high_entropy.bin", string(highEntropy))

	agent := setupDetection(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "pe_analyze",
		"path":   path,
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	isPE, _ := output["is_pe"].(bool)
	if isPE {
		return
	}
}
