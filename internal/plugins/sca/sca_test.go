package sca

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestSCARunnerValidPolicy(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("SCA tests require Unix")
	}

	policy := `
policy:
  id: "test_policy"
  name: "Test Policy"
checks:
  - id: 100
    title: "Check /bin/sh exists"
    condition: all
    rules:
      - "f:/bin/sh -> r:."
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}

	pass, _ := output["pass"].(int)
	if pass != 1 {
		t.Fatalf("expected 1 pass, got %d (fail: %v)", pass, output["fail"])
	}
}

func TestSCARunnerFileCheck(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("this test requires Unix filesystem")
	}

	policy := `
policy:
  id: "test_file"
  name: "File Check Test"
checks:
  - id: 200
    title: "Check /bin/sh exists and has expected content"
    condition: all
    rules:
      - "f:/bin/sh -> r:ELF"
`
	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}

	pass, _ := output["pass"].(int)
	if pass != 1 {
		t.Fatalf("expected 1 pass, got %d (score: %v, fail: %v)", pass, output["score"], output["fail"])
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
		t.Fatalf("expected 1 pass, got %d (fail: %v)", pass, output["fail"])
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
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("SCA tests require Unix")
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

	pass, _ := output["pass"].(int)
	if pass != 1 {
		t.Fatalf("expected 1 pass (nonexistent file should not match), got %d", pass)
	}
}

func TestSCARunnerFromEmbedded(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SCA embedded policy test requires Linux")
	}

	policy := DetectOSPolicy()
	if policy == nil {
		t.Skip("no matching policy")
	}

	a := New()
	output, err := a.runPolicy(context.Background(), map[string]any{"policy_data": policy.Data})
	if err != nil {
		t.Fatalf("runPolicy: %v", err)
	}

	t.Logf("Policy: %s", output["policy"])
	t.Logf("Pass: %v | Fail: %v | Score: %v", output["pass"], output["fail"], output["score"])

	total, _ := output["total"].(int)
	if total == 0 {
		t.Error("expected at least one check in the policy")
	}
}

func init() {
	_ = os.Getenv
	_ = context.Background
}
