package sca

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestSCARunnerValidPolicy(t *testing.T) {
	policy := `
policy:
  id: "test_policy"
  name: "Test Policy"
checks:
  - id: 100
    title: "Check OS matches"
    condition: all
    rules:
      - "f:/etc/os-release -> r:ID"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}

	t.Logf("Policy: %v", output["policy"])
	t.Logf("Pass: %v", output["pass"])
	t.Logf("Fail: %v", output["fail"])
	t.Logf("Score: %v", output["score"])
}

func TestSCARunnerFileCheck(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("this test requires Unix filesystem")
	}

	tmpFile := t.TempDir() + "/test_config.conf"
	os.WriteFile(tmpFile, []byte("OPTION=YES\n"), 0644)

	policy := `
policy:
  id: "test_file"
  name: "File Check Test"
checks:
  - id: 200
    title: "Check config file exists"
    condition: all
    rules:
      - "f:` + tmpFile + ` -> r:OPTION=YES"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}

	pass, _ := output["pass"].(int)
	if pass != 1 {
		t.Fatalf("expected 1 pass, got %d (score: %v)", pass, output["score"])
	}
}

func TestSCARunnerCommandCheck(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("this test requires Unix")
	}

	policy := `
policy:
  id: "test_cmd"
  name: "Command Check Test"
checks:
  - id: 300
    title: "Check whoami works"
    condition: all
    rules:
      - "c:whoami -> r:."
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}

	pass, _ := output["pass"].(int)
	if pass != 1 {
		t.Fatalf("expected 1 pass, got %d", pass)
	}
}

func TestSCARunnerOSDetection(t *testing.T) {
	policy := DetectOSPolicy()
	if policy == nil {
		t.Logf("No matching policy for OS: %s", runtime.GOOS)
		return
	}
	t.Logf("Detected policy: %s (%s)", policy.ID, policy.Name)
	if !strings.Contains(policy.ID, runtime.GOOS) && !strings.Contains(policy.Name, runtime.GOOS) {
		t.Logf("Policy %s may not be exact match for OS %s", policy.ID, runtime.GOOS)
	}
}

func TestSCARunnerNegativeCondition(t *testing.T) {
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

	pass, _ := output["pass"].(int)
	if pass != 1 {
		t.Fatalf("expected 1 pass (nonexistent file should not match), got %d", pass)
	}
}
