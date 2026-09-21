package playbook

import (
	"testing"
)

func TestInterpolateString(t *testing.T) {
	scope := &Scope{
		Input: map[string]any{
			"hash":   "abc123",
			"path":   "/tmp/test.exe",
			"number": 42,
		},
		Results: map[string]any{
			"detection.hash_lookup": map[string]any{
				"reputation": "malicious",
				"score":      0.95,
			},
		},
	}

	tests := []struct {
		input string
		want  string
	}{
		{"${input.hash}", "abc123"},
		{"${input.path}", "/tmp/test.exe"},
		{"checking ${input.hash}", "checking abc123"},
		{"path: ${input.path}, hash: ${input.hash}", "path: /tmp/test.exe, hash: abc123"},
		{"no variables here", "no variables here"},
		{"${input.number}", "42"},
	}

	for _, tt := range tests {
		got, err := interpolateString(tt.input, scope)
		if err != nil {
			t.Errorf("interpolateString(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("interpolateString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestInterpolateMap(t *testing.T) {
	scope := &Scope{
		Input: map[string]any{
			"hash": "abc123",
			"path": "/tmp/test.exe",
		},
		Results: map[string]any{},
	}

	input := map[string]any{
		"hash_value": "${input.hash}",
		"file_path":  "${input.path}",
		"static":     "hello",
	}

	result, err := interpolate(input, scope)
	if err != nil {
		t.Fatalf("interpolate error: %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("result not a map")
	}

	if resultMap["hash_value"] != "abc123" {
		t.Fatalf("hash_value = %v, want abc123", resultMap["hash_value"])
	}
	if resultMap["file_path"] != "/tmp/test.exe" {
		t.Fatalf("file_path = %v, want /tmp/test.exe", resultMap["file_path"])
	}
	if resultMap["static"] != "hello" {
		t.Fatalf("static = %v, want hello", resultMap["static"])
	}
}

func TestInterpolateResults(t *testing.T) {
	scope := &Scope{
		Input: map[string]any{},
		Results: map[string]any{
			"detection.hash_lookup": map[string]any{
				"reputation": "malicious",
				"score":      0.95,
			},
		},
	}

	got, err := interpolateString("${outputs.detection.hash_lookup.reputation}", scope)
	if err != nil {
		t.Fatalf("interpolateString error: %v", err)
	}

	if got != "malicious" {
		t.Fatalf("expected malicious, got %s", got)
	}
}

func TestInterpolateMissingKey(t *testing.T) {
	scope := &Scope{
		Input:   map[string]any{},
		Results: map[string]any{},
	}

	// Fail-closed: missing => error, never "".
	if _, err := interpolateString("${input.missing}", scope); err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestEvaluateCondition(t *testing.T) {
	scope := &Scope{
		Input: map[string]any{
			"hash": "abc123",
			"name": "test.exe",
		},
		Results: map[string]any{},
	}

	tests := []struct {
		expr    string
		want    bool
		wantErr bool
	}{
		{"${input.hash}", true, false},
		{"${input.name} == \"test.exe\"", true, false},
		{"${input.name} == \"other.exe\"", false, false},
		{"${input.name} != \"other.exe\"", true, false},
		{"", true, false},
		// Fail-closed: missing ref errors (no empty iptables/mv/kill).
		{"${input.nothere}", false, true},
		// Richer if: >= and contains and CIDR.
		{"${input.count} >= 3", true, false},
		{"${input.name} contains \"test\"", true, false},
		{"${input.ip} in_cidr \"10.0.0.0/8\"", true, false},
		{"${input.ip} in_cidr \"192.168.0.0/16\"", false, false},
	}

	scope.Input["count"] = "5"
	scope.Input["ip"] = "10.1.2.3"

	for _, tt := range tests {
		got, err := evaluateCondition(tt.expr, scope)
		if tt.wantErr {
			if err == nil {
				t.Errorf("evaluateCondition(%q) expected error, got nil", tt.expr)
			}
			continue
		}
		if err != nil {
			t.Errorf("evaluateCondition(%q) error: %v", tt.expr, err)
			continue
		}
		if got != tt.want {
			t.Errorf("evaluateCondition(%q) = %v, want %v", tt.expr, got, tt.want)
		}
	}
}

func TestEvaluateConditionWithResult(t *testing.T) {
	scope := &Scope{
		Input: map[string]any{},
		Results: map[string]any{
			"detection.hash_lookup": map[string]any{
				"reputation": "malicious",
			},
		},
	}

	ok, err := evaluateCondition("${outputs.detection.hash_lookup.reputation} == \"malicious\"", scope)
	if err != nil {
		t.Fatalf("evaluateCondition error: %v", err)
	}
	if !ok {
		t.Fatal("expected condition to be true")
	}
}
