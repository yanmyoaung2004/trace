package sca

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSCARunnerFileCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA file check requires Unix")
	}
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

	// Replicate the EXACT code from evaluateRule's c: handler
	rule := "c:echo hello -> r:hello"
	parts := strings.SplitN(rule, "->", 2)
	cmdStr := strings.TrimSpace(strings.TrimPrefix(parts[0], "c:"))
	expected := strings.TrimSpace(strings.TrimPrefix(parts[1], "r:"))
	t.Logf("cmdStr=%q expected=%q", cmdStr, expected)

	cmdParts := strings.Fields(cmdStr)
	t.Logf("cmdParts=%v", cmdParts)
	t.Logf("allowedCmds[echo]=%v", allowedCmds["echo"])

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)
	out, err := cmd.Output()
	t.Logf("exec.CommandContext echo: out=%q err=%v", string(out), err)
	if err != nil {
		t.Fatalf("CommandContext failed: %v", err)
	}

	matched, _ := regexp.MatchString(expected, string(out))
	t.Logf("MatchString(%q, %q)=%v", expected, string(out), matched)
	if !matched {
		t.Fatalf("regexp.MatchString failed: expected=%q output=%q", expected, string(out))
	}

	a := New()
	ok, err := a.evaluateRule(context.Background(), rule)
	if err != nil {
		t.Fatalf("evaluateRule error: %v", err)
	}
	if !ok {
		t.Fatalf("evaluateRule returned false — CommandContext output=%q, expected=%q, matched=%v",
			string(out), expected, matched)
	}
}

func TestSCARunnerCommandWithContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCA command check requires Unix")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "echo", "hello")
	out, err := cmd.Output()
	t.Logf("CommandContext(echo, hello): out=%q err=%v", string(out), err)
	if err != nil {
		t.Fatalf("CommandContext failed: %v", err)
	}

	matched, _ := regexp.MatchString("hello", string(out))
	t.Logf("MatchString hello in output: %v", matched)
	if !matched {
		t.Fatalf("expected hello in output")
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
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory check failed — dir=%q names=%v", dir, names)
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
	_ = fmt.Sprintf
	_ = os.Getenv
	_ = strings.HasPrefix
	_ = context.Background
}
