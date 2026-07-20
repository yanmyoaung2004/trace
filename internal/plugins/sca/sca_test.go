package sca

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSCARunnerFileCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA file check requires Unix")
	}

	tmp := t.TempDir()
	tmpFile := tmp + "/test.conf"
	os.WriteFile(tmpFile, []byte("ENABLED=yes\n"), 0644)

	policy := `
policy:
  id: "test_file"
  name: "File Check"
checks:
  - id: 200
    title: "Check file exists"
    condition: all
    rules:
      - "f:` + tmpFile + ` -> r:ENABLED"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}
	pass, ok := output["pass"].(int)
	if !ok || pass != 1 {
		t.Fatalf("expected 1 pass, got %v (fail: %v, error: %v)", pass, output["fail"], output["error"])
	}
}

func TestSCARunnerCommandCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA command check requires Unix")
	}

	policy := `
policy:
  id: "test_cmd"
  name: "Command Check"
checks:
  - id: 300
    title: "Check echo works"
    condition: all
    rules:
      - "c:echo hello -> r:hello"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}
	pass, ok := output["pass"].(int)
	if !ok || pass != 1 {
		t.Fatalf("expected 1 pass, got %v (fail: %v)", pass, output["fail"])
	}
}

func TestSCARunnerNegativeCondition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA negative check requires Unix")
	}

	policy := `
policy:
  id: "test_neg"
  name: "Negative Test"
checks:
  - id: 400
    title: "Ensure nonexistent file does not exist"
    condition: all
    rules:
      - "not f:/nonexistent_path_xyzzy_12345 -> r:test"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}
	pass, ok := output["pass"].(int)
	if !ok || pass != 1 {
		t.Fatalf("expected 1 pass, got %d", pass)
	}
}

func TestSCARunnerDirectoryCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA directory check requires Unix")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.conf"), []byte("ENABLED=yes\n"), 0644)

	policy := `
policy:
  id: "test_dir"
  name: "Directory Check"
checks:
  - id: 500
    title: "Check dir has config file"
    condition: any
    rules:
      - "d:` + dir + ` -> r:\.conf -> r:ENABLED"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}
	pass, ok := output["pass"].(int)
	if !ok || pass != 1 {
		t.Fatalf("expected 1 pass, got %v (fail: %v)", pass, output["fail"])
	}
}

func TestSCARunnerMultipleChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA multi-check requires Unix")
	}

	tmp := t.TempDir()
	tmpFile := tmp + "/test.conf"
	os.WriteFile(tmpFile, []byte("ok=yes\n"), 0644)

	policy := `
policy:
  id: "test_multi"
  name: "Multiple Checks"
checks:
  - id: 600
    title: "config exists"
    condition: all
    rules:
      - "f:` + tmpFile + ` -> r:ok"
  - id: 601
    title: "echo works"
    condition: all
    rules:
      - "c:echo ok -> r:ok"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}
	t.Logf("Pass: %v | Fail: %v | Score: %v", output["pass"], output["fail"], output["score"])
	total, _ := output["total"].(int)
	if total != 2 {
		t.Fatalf("expected 2 total checks, got %d", total)
	}
}

func init() {
	_ = os.Getenv
	_ = context.Background
}
