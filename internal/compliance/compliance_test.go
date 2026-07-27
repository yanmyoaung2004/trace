package compliance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

// mockSCA returns realistic scan results with compliance mappings to real framework controls.
type mockSCA struct {
	results []map[string]any
}

func (m *mockSCA) Name() string { return "mock_sca" }
func (m *mockSCA) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	if m.results != nil {
		res := make([]any, len(m.results))
		for i, r := range m.results {
			res[i] = r
		}
		return agent.Output{"results": res}, nil
	}
	return agent.Output{
		"results": []any{
			map[string]any{
				"id":    1,
				"title": "Network segmentation check",
				"status": "pass",
				"compliance": map[string][]string{
					"pci_dss_v4.0": {"1.4"},
					"nist_sp_800-53": {"SC-7"},
				},
			},
			map[string]any{
				"id":    2,
				"title": "MFA enforcement",
				"status": "pass",
				"compliance": map[string][]string{
					"pci_dss_v4.0": {"8.3.2"},
					"nist_sp_800-53": {"IA-2"},
				},
			},
			map[string]any{
				"id":    3,
				"title": "Encryption in transit",
				"status": "fail",
				"compliance": map[string][]string{
					"pci_dss_v4.0": {"4.1"},
				},
			},
			map[string]any{
				"id":    4,
				"title": "Access control review",
				"status": "pass",
				"compliance": map[string][]string{
					"pci_dss_v4.0": {"8.2.1"},
					"hipaa": {"164.312(a)(1)"},
				},
			},
			map[string]any{
				"id":    5,
				"title": "Audit logging",
				"status": "fail",
				"compliance": map[string][]string{
					"pci_dss_v4.0": {"10.2.2", "10.2.3"},
					"soc_2": {"CC6.1"},
				},
			},
			map[string]any{
				"id":    6,
				"title": "Data encryption at rest",
				"status": "pass",
				"compliance": map[string][]string{
					"gdpr": {"article_32"},
				},
			},
		},
	}, nil
}
func (m *mockSCA) Capabilities() []agent.Capability { return nil }

func TestFrameworksExist(t *testing.T) {
	if len(Frameworks) == 0 {
		t.Fatal("expected at least one framework")
	}
}

func TestPCI_DSS_v4_HasControls(t *testing.T) {
	fw, ok := Frameworks["pci_dss_v4.0"]
	if !ok {
		t.Fatal("PCI DSS v4.0 not found")
	}
	if fw.ID != "pci_dss_v4.0" {
		t.Errorf("id = %q", fw.ID)
	}
	if len(fw.Controls) == 0 {
		t.Error("expected controls")
	}
}

func TestGDPR_HasControls(t *testing.T) {
	fw, ok := Frameworks["gdpr"]
	if !ok {
		t.Fatal("GDPR not found")
	}
	if fw.Name != "GDPR" {
		t.Errorf("name = %q", fw.Name)
	}
}

func TestAllFrameworksHaveIDs(t *testing.T) {
	for id, fw := range Frameworks {
		if fw.ID != id {
			t.Errorf("framework %q has mismatched ID %q", id, fw.ID)
		}
		if len(fw.Controls) == 0 {
			t.Errorf("framework %q has no controls", id)
		}
	}
}

func TestAllControlsHaveIDs(t *testing.T) {
	for _, fw := range Frameworks {
		for _, c := range fw.Controls {
			if c.ID == "" {
				t.Errorf("control in %s has empty ID", fw.ID)
			}
		}
	}
}

func TestNewReportEngine(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	if e == nil {
		t.Fatal("expected engine")
	}
}

func TestGenerateReport_UnknownFramework(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	_, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
}

func TestGenerateReport_PCI_DSS_WithRealData(t *testing.T) {
	e := newTestEngine(t)
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Framework != "pci_dss_v4.0" {
		t.Errorf("framework = %q", report.Framework)
	}
	if report.Score <= 0 || report.Score > 100 {
		t.Errorf("score out of range: %.1f", report.Score)
	}
	if report.Passed+report.Failed+report.NotCovered != report.Total {
		t.Errorf("%d+%d+%d != %d total", report.Passed, report.Failed, report.NotCovered, report.Total)
	}
}

func TestGenerateReport_PCI_DSS_Score(t *testing.T) {
	e := newTestEngine(t)
	report, _ := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	// mock SCA maps: 1.4(pass), 8.3.2(pass), 4.1(fail), 8.2.1(pass), 10.2.2(fail), 10.2.3(fail)
	// So 3 passed inputs across controls. PCI DSS has 14 controls.
	// Controls matched: 1.4(pass), 4.1(fail), 8.2.1(pass), 8.3.2(pass), 10.2.2(fail) — each has matched status
	// SCA statuses: pass->pass, fail->fail. So 3 passed controls, 2 failed, 9 not-covered.
	if report.Passed < 2 || report.Failed < 1 {
		t.Errorf("expected at least 2 passed and 1 failed with real SCA data, got passed=%d failed=%d not_covered=%d",
			report.Passed, report.Failed, report.NotCovered)
	}
}

// --- Manual assessment flow-through tests ---

func TestManualAssessmentFlow(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// Set a control as passed
	if err := e.SetManualAssessment(ctx, "pci_dss_v4.0", "6.2", "pass", "Patches applied within SLA"); err != nil {
		t.Fatal(err)
	}

	report, err := e.GenerateReport(ctx, ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatal(err)
	}

	// Find control 6.2 in results
	for _, cr := range report.Results {
		if cr.ID == "6.2" {
			if cr.Status != "pass" {
				t.Errorf("control 6.2 status = %q, want pass", cr.Status)
			}
			break
		}
	}
}

func TestManualAssessmentScoreChanges(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// Before: only SCA results
	reportBefore, _ := e.GenerateReport(ctx, ReportOptions{Framework: "pci_dss_v4.0"})

	// Set ALL controls as passed via manual assessment
	for _, c := range Frameworks["pci_dss_v4.0"].Controls {
		e.SetManualAssessment(ctx, "pci_dss_v4.0", c.ID, "pass", "Automated test pass")
	}

	reportAfter, _ := e.GenerateReport(ctx, ReportOptions{Framework: "pci_dss_v4.0"})
	if reportAfter.Score < reportBefore.Score {
		t.Errorf("score dropped after setting all controls passed: %.1f → %.1f", reportBefore.Score, reportAfter.Score)
	}
	if reportAfter.Passed < reportBefore.Passed {
		t.Errorf("passed count dropped: %d → %d", reportBefore.Passed, reportAfter.Passed)
	}
	// At minimum, controls not touched by SCA should now be passed
	if reportAfter.NotCovered > 0 {
		t.Errorf("expected 0 not-covered after all passed, got %d", reportAfter.NotCovered)
	}
}

func TestManualAssessmentAllFail(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	for _, c := range Frameworks["pci_dss_v4.0"].Controls {
		e.SetManualAssessment(ctx, "pci_dss_v4.0", c.ID, "fail", "Failing for test")
	}

	report, _ := e.GenerateReport(ctx, ReportOptions{Framework: "pci_dss_v4.0"})
	if report.Failed != report.Total {
		t.Errorf("expected all %d failed, got %d", report.Total, report.Failed)
	}
	if report.Score != 0 {
		t.Errorf("expected 0%% score after all failed, got %.1f%%", report.Score)
	}
}

// --- Evidence integration tests ---

func TestEvidenceFlow(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	dir := t.TempDir()

	// Add evidence file
	evPath := filepath.Join(dir, "mfa_config.txt")
	if err := os.WriteFile(evPath, []byte("MFA enabled on all admin accounts"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := e.AddEvidence(ctx, "pci_dss_v4.0", "8.3.2", "MFA configured for all CDE access", evPath); err != nil {
		t.Fatal(err)
	}

	report, err := e.GenerateReport(ctx, ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, cr := range report.Results {
		if cr.ID == "8.3.2" {
			found = true
			if len(cr.Details) == 0 {
				t.Error("expected evidence details for control 8.3.2")
			}
			break
		}
	}
	if !found {
		t.Error("control 8.3.2 not found in report")
	}
}

// --- SCA parse and merge tests ---

func TestSCAParseResults(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// Engine already ran tryAutoScan during GenerateReport
	report, err := e.GenerateReport(ctx, ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatal(err)
	}

	// SCA should have matched 5 controls: 1.4(pass), 8.3.2(pass), 4.1(fail), 8.2.1(pass), 10.2.2(fail)
	matched := 0
	for _, cr := range report.Results {
		for _, d := range cr.Details {
			if strings.Contains(d.Title, "SCA") {
				matched++
			}
		}
	}
	if matched < 3 {
		t.Errorf("expected at least 3 SCA-matched controls, got %d", matched)
	}
}

func TestMergeManualAndSCA(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// Set a manual fail that SCA says pass
	e.SetManualAssessment(ctx, "pci_dss_v4.0", "1.4", "fail", "Network segmentation incomplete")
	// Set a manual pass that SCA says fail
	e.SetManualAssessment(ctx, "pci_dss_v4.0", "4.1", "pass", "TLS 1.3 implemented")

	report, _ := e.GenerateReport(ctx, ReportOptions{Framework: "pci_dss_v4.0"})

	for _, cr := range report.Results {
		switch cr.ID {
		case "1.4":
			if cr.Status != "fail" {
				t.Errorf("control 1.4: expected manual 'fail' to override SCA 'pass', got %q", cr.Status)
			}
			if len(cr.Details) < 2 {
				t.Errorf("control 1.4: expected 2+ details (manual + SCA), got %d", len(cr.Details))
			}
		case "4.1":
			if cr.Status != "fail" {
				t.Errorf("control 4.1: SCA says 'fail' and manual says 'pass' should still fail, got %q", cr.Status)
			}
		}
	}
}

// --- Edge case tests ---

func TestGenerateReport_NoSCA(t *testing.T) {
	e := NewReportEngine(&noopAgent{})
	e.DataDir = t.TempDir()
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Score != 0 {
		t.Errorf("expected 0%% score with no SCA and no assessments, got %.1f%%", report.Score)
	}
	if report.NotCovered != report.Total {
		t.Errorf("expected all not-covered, got %d/%d", report.NotCovered, report.Total)
	}
}

func TestGenerateReport_AllFrameworks(t *testing.T) {
	e := newTestEngine(t)
	for id := range Frameworks {
		t.Run(id, func(t *testing.T) {
			report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: id})
			if err != nil {
				t.Fatal(err)
			}
			if report.Total == 0 {
				t.Error("expected non-zero total controls")
			}
			if report.Score < 0 || report.Score > 100 {
				t.Errorf("score out of range: %.1f", report.Score)
			}
		})
	}
}

func TestGetHistory(t *testing.T) {
	e := newTestEngine(t)
	dir := t.TempDir()
	e.DataDir = dir

	// Generate a report to trigger snapshot
	e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})

	points, err := e.GetHistory("pci_dss_v4.0", 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) < 1 {
		t.Error("expected at least 1 score point")
	}
	if len(points) > 0 && points[0].Score <= 0 {
		t.Errorf("expected positive score, got %.1f", points[0].Score)
	}
}

func TestGetHistory_EmptyForUnknownFramework(t *testing.T) {
	e := newTestEngine(t)
	points, err := e.GetHistory("nonexistent", 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 0 {
		t.Errorf("expected empty history, got %d points", len(points))
	}
}

// --- Renderer content tests ---

func TestReportRenderText(t *testing.T) {
	e := newTestEngine(t)
	report, _ := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	s := report.RenderText()
	if s == "" {
		t.Fatal("expected non-empty string")
	}
	if !strings.Contains(s, "Score") {
		t.Errorf("expected Score in report text: %s", s[:min(200, len(s))])
	}
	if !strings.Contains(s, "Framework") {
		t.Error("expected Framework in report text")
	}
}

func TestReportRenderMarkdown(t *testing.T) {
	e := newTestEngine(t)
	report, _ := e.GenerateReport(context.Background(), ReportOptions{Framework: "gdpr"})
	md := report.RenderMarkdown()
	if !strings.Contains(md, "gdpr") {
		t.Error("expected gdpr in markdown output")
	}
	if !strings.Contains(md, "|") {
		t.Error("expected markdown table")
	}
}

func TestReportRenderHTML(t *testing.T) {
	e := newTestEngine(t)
	report, _ := e.GenerateReport(context.Background(), ReportOptions{Framework: "hipaa"})
	html := report.RenderHTML()
	if !strings.Contains(html, "<html") {
		t.Error("expected HTML tag")
	}
	if !strings.Contains(html, "hipaa") {
		t.Error("expected hipaa in HTML")
	}
}

func TestReportRenderJSON(t *testing.T) {
	e := newTestEngine(t)
	report, _ := e.GenerateReport(context.Background(), ReportOptions{Framework: "soc_2"})
	json, err := report.RenderJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(json, "soc_2") {
		t.Error("expected soc_2 in JSON")
	}
	if !strings.Contains(json, "framework") {
		t.Error("expected framework in JSON")
	}
}

func TestReportWriteFile(t *testing.T) {
	e := newTestEngine(t)
	report, _ := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	dir := t.TempDir()

	tests := []struct {
		file     string
		contains string
	}{
		{"report.html", "<html"},
		{"report.md", "pci_dss_v4.0"},
		{"report.json", "pci_dss_v4.0"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join(dir, tt.file)
			if err := report.WriteFile(path); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tt.contains) {
				t.Errorf("%s: expected %q in output", tt.file, tt.contains)
			}
		})
	}
}

// --- Evidence tests ---

func TestEvidenceData(t *testing.T) {
	ev := Evidence{
		ID:          "ev-1",
		ControlID:   "8.2.1",
		Framework:   "pci_dss_v4.0",
		Description: "MFA is enabled",
		Status:      "pass",
		Assessor:    "auditor",
	}
	if ev.ID != "ev-1" {
		t.Errorf("id = %q", ev.ID)
	}
}

// --- Helpers ---

func newTestEngine(t *testing.T) *ReportEngine {
	t.Helper()
	e := NewReportEngine(&mockSCA{})
	e.DataDir = t.TempDir()
	return e
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type noopAgent struct{}

func (n *noopAgent) Name() string { return "noop" }
func (n *noopAgent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	return agent.Output{}, nil
}
func (n *noopAgent) Capabilities() []agent.Capability { return nil }
