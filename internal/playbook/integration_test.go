package playbook

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "test.db")+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLoadAllPlaybooks(t *testing.T) {
	e := New()
	if err := e.LoadBuiltin(); err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	list := e.List()
	if len(list) == 0 {
		t.Fatal("expected at least 1 playbook")
	}
	t.Logf("loaded %d playbooks", len(list))
	for _, pb := range list {
		t.Logf("  - %s: %s", pb.Name, pb.Description)
		if pb.Name == "" {
			t.Error("playbook has empty name")
		}
		if len(pb.Steps) == 0 {
			t.Errorf("playbook %q has no steps", pb.Name)
		}
	}
}

func TestPlaybookByName(t *testing.T) {
	e := New()
	e.LoadBuiltin()

	tests := []struct {
		name string
		want int
	}{
		{"hash-lookup", 4},
		{"ip-reputation", 4},
		{"file-analysis", 4},
		{"domain-reputation", 3},
		{"email-analysis", 5},
		{"network-scan", 7},
		{"log-analysis", 6},
		{"cve-lookup", 1},
		{"mitre-lookup", 1},
		{"slack-notify", 1},
		{"discord-notify", 1},
		{"block-ip", 1},
		{"quarantine-file", 1},
		{"kill-process", 1},
		{"restart-service", 1},
		{"rollback-action", 1},
		{"full-enrich", 7},
		{"rootkit-scan", 4},
		{"compliance-scan", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := e.Get(tt.name)
			if pb == nil {
				t.Fatalf("playbook %q not found", tt.name)
			}
			if len(pb.Steps) != tt.want {
				t.Errorf("expected %d steps, got %d", tt.want, len(pb.Steps))
			}
			for i, step := range pb.Steps {
				if step.Agent == "" {
					t.Errorf("step %d has empty agent", i)
				}
				if step.Action == "" {
					t.Errorf("step %d has empty action", i)
				}
			}
		})
	}
}

func TestPlaybookByNameExists(t *testing.T) {
	e := New()
	e.LoadBuiltin()

	expectedPlaybooks := []string{
		"hash-lookup", "file-analysis", "ip-reputation",
		"domain-reputation", "email-analysis", "network-scan", "log-analysis",
		"cve-lookup", "mitre-lookup",
		"block-ip", "quarantine-file", "kill-process", "restart-service", "rollback-action",
		"slack-notify", "discord-notify",
		"windows-event-analysis", "registry-check", "ip-enrich",
	}

	for _, name := range expectedPlaybooks {
		t.Run(name, func(t *testing.T) {
			pb := e.Get(name)
			if pb == nil {
				t.Fatalf("playbook %q not found", name)
			}
			if len(pb.Steps) == 0 {
				t.Errorf("playbook %q has no steps", name)
			}
		})
	}
}

func TestScopeInterpolation(t *testing.T) {
	scope := &Scope{
		Input: map[string]any{
			"hash": "abc123",
			"ip":   "10.0.0.1",
		},
		Results: map[string]any{
			"detection.hash_lookup": map[string]any{
				"reputation": "malicious",
				"confidence": 0.95,
			},
		},
	}

	tests := []struct {
		input string
		want  string
	}{
		{"${input.hash}", "abc123"},
		{"${input.ip}", "10.0.0.1"},
		{"${outputs.detection.hash_lookup.reputation}", "malicious"},
		{"plain text", "plain text"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := interpolateString(tt.input, scope)
			if err != nil {
				t.Fatalf("interpolate(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConditionEvaluation(t *testing.T) {
	scope := &Scope{
		Results: map[string]any{
			"detection.yara_scan": map[string]any{
				"count": "3",
			},
			"knowledge.mitre_lookup": map[string]any{
				"found": "true",
			},
		},
	}

	tests := []struct {
		expr string
		want bool
	}{
		{`${result.detection.yara_scan.count} != "0"`, true},
		{`${result.detection.yara_scan.count} == "0"`, false},
		{`${outputs.knowledge.mitre_lookup.found} == "true"`, true},
		{`${outputs.knowledge.mitre_lookup.found} != "true"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := evaluateCondition(tt.expr, scope)
			if err != nil {
				t.Fatalf("evaluateCondition(%q): %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExecutorStepValidation(t *testing.T) {
	e := New()
	e.LoadBuiltin()

	for _, pb := range e.List() {
		t.Run(pb.Name, func(t *testing.T) {
			for i, step := range pb.Steps {
				if step.Timeout != "" {
					_, err := time.ParseDuration(step.Timeout)
					if err != nil {
						t.Errorf("step %d: invalid timeout %q: %v", i, step.Timeout, err)
					}
				}
				if _, ok := validAgents[step.Agent]; !ok {
					t.Errorf("step %d: unknown agent %q", i, step.Agent)
				}
			}
		})
	}
}

var validAgents = map[string]bool{
	"sift":       true,
	"archive":    true,
	"dispatch":   true,
	"response":   true,
	"notifier":   true,
	"splunk":     true,
	"elastic":    true,
	"exporter":   true,
	"abuseipdb":  true,
	"otx":        true,
	"sca":        true,
}

func init() {
	_ = context.Background
}
