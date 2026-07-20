package sca

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestSCARunnerFileCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA file check requires Unix")
	}

	// Bypass evaluateRule entirely — test raw Go operations
	data, err := os.ReadFile("/etc/hosts")
	t.Logf("ReadFile(/etc/hosts): err=%v len=%d", err, len(data))
	if err != nil {
		t.Skipf("/etc/hosts not readable: %v", err)
	}
	matched, _ := regexp.MatchString("localhost", string(data))
	t.Logf("MatchString localhost in /etc/hosts: %v", matched)
	if !matched {
		t.Fatalf("/etc/hosts content does not contain localhost: %q", string(data))
	}

	// Now test through evaluateRule
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.txt")
	os.WriteFile(path, []byte("hello world\n"), 0644)

	a := New()
	ok, err := a.evaluateRule(context.Background(), "f:"+path+" -> r:hello")
	if err != nil {
		t.Fatalf("evaluateRule error: %v", err)
	}
	if !ok {
		content, _ := os.ReadFile(path)
		t.Fatalf("evaluateRule=false — path=%q content=%q", path, string(content))
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

	// Bypass evaluateRule entirely — test raw Go operations
	echoPath, _ := exec.LookPath("echo")
	t.Logf("LookPath(echo): path=%q", echoPath)

	out, err := exec.Command("echo", "hello").Output()
	t.Logf("exec echo hello: out=%q err=%v", string(out), err)
	if err != nil {
		t.Skipf("echo not available: %v", err)
	}

	matched, _ := regexp.MatchString("hello", string(out))
	t.Logf("MatchString hello in output: %v", matched)

	// Now test evaluateRule with echo
	a := New()
	ok, err := a.evaluateRule(context.Background(), "c:echo hello -> r:hello")
	if err != nil {
		t.Fatalf("evaluateRule error: %v", err)
	}
	if !ok {
		t.Fatalf("evaluateRule returned false — echo works, output=%q", string(out))
	}
}

func TestSCARunnerCommandCheckBuiltin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA command check requires Unix")
	}

	// Use 'true' which always exits 0, plus explicit output check
	out, err := exec.Command("true").Output()
	t.Logf("exec true: out=%q err=%v", string(out), err)

	// Test with cat which is in allowedCmds and always available
	out2, err2 := exec.Command("cat", "/etc/hosts").Output()
	t.Logf("exec cat /etc/hosts: len=%d err=%v", len(out2), err2)

	a := New()
	ok, err := a.evaluateRule(context.Background(), "c:cat /etc/hosts -> r:localhost")
	if err != nil {
		t.Fatalf("evaluateRule cat: %v", err)
	}
	if !ok {
		t.Fatalf("evaluateRule returned false for cat /etc/hosts")
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
		entries, _ := os.ReadDir(dir)
		t.Fatalf("directory check failed — dir=%q files=%v", dir, entries)
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
	_ = strings.HasPrefix
	_ = context.Background
}
