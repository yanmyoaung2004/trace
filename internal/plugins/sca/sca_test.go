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
	a := New()
	ok, err := a.evaluateRule(context.Background(), "f:/etc/hosts -> r:localhost")
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if !ok {
		t.Fatal("expected /etc/hosts to match localhost")
	}
}

func TestSCARunnerFileCheckNonExistent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA file check requires Unix")
	}
	a := New()
	ok, err := a.evaluateRule(context.Background(), "f:/nonexistent_path_xyzzy -> r:test")
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if ok {
		t.Fatal("expected nonexistent file to not match")
	}
}

func TestSCARunnerCommandCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA command check requires Unix")
	}
	a := New()
	ok, err := a.evaluateRule(context.Background(), "c:echo hello -> r:hello")
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if !ok {
		t.Fatal("expected echo hello to match r:hello")
	}
}

func TestSCARunnerNegativeCondition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA negative check requires Unix")
	}
	a := New()
	ok, err := a.evaluateRule(context.Background(), "not f:/nonexistent_path_xyzzy_12345 -> r:test")
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if !ok {
		t.Fatal("expected negated check to pass for nonexistent file")
	}
}

func TestSCARunnerDirectoryCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA directory check requires Unix")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.conf"), []byte("ENABLED=yes\n"), 0644)
	a := New()
	ok, err := a.evaluateRule(context.Background(), "d:"+dir+" -> r:\\.conf -> r:ENABLED")
	if err != nil {
		t.Fatalf("evaluateRule: %v", err)
	}
	if !ok {
		t.Fatal("expected directory check to find ENABLED in .conf file")
	}
}

func TestSCARunnerPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA policy requires Unix")
	}

	policy := `
policy:
  id: "test_multi"
  name: "Multiple Checks"
checks:
  - id: 600
    title: "hosts exists"
    condition: all
    rules:
      - "f:/etc/hosts -> r:localhost"
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
	t.Logf("Pass: %v | Fail: %v | Score: %v | Error: %v | Results: %v",
		output["pass"], output["fail"], output["score"], output["error"], output["results"])
	total, _ := output["total"].(int)
	if total != 2 {
		t.Fatalf("expected 2 total checks, got %d", total)
	}
	pass, _ := output["pass"].(int)
	if pass != 2 {
		t.Fatalf("expected 2 passes, got %d", pass)
	}
}

func init() {
	_ = os.Getenv
	_ = context.Background
}
