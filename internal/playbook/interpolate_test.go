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

	got, err := interpolateString("${input.missing}", scope)
	if err != nil {
		t.Fatalf("interpolateString should not error, got: %v", err)
	}

	if got != "" {
		t.Fatalf("expected empty string for missing key, got %s", got)
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
		expr string
		want bool
	}{
		{"${input.hash}", true},
		{"${input.name} == \"test.exe\"", true},
		{"${input.name} == \"other.exe\"", false},
		{"${input.name} != \"other.exe\"", true},
		{"", true},
		{"${input.nothere}", false},
	}

	for _, tt := range tests {
		got, err := evaluateCondition(tt.expr, scope)
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
