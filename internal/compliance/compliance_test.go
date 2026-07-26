package compliance

import (
	"context"
	"strings"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type mockSCA struct{}

func (m *mockSCA) Name() string { return "mock_sca" }
func (m *mockSCA) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	return agent.Output{}, nil
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
	if e.Hostname == "" {
		t.Log("hostname is empty (expected in some environments)")
	}
}

func TestGenerateReport_UnknownFramework(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	_, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
}

func TestGenerateReport_PCI_DSS(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatal(err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
	if report.Framework != "pci_dss_v4.0" {
		t.Errorf("framework = %q", report.Framework)
	}
	if report.GeneratedAt == "" {
		t.Error("expected GeneratedAt")
	}
	if report.Score < 0 || report.Score > 100 {
		t.Errorf("score out of range: %f", report.Score)
	}
}

func TestGenerateReport_GDPR(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "gdpr"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Framework != "gdpr" {
		t.Errorf("framework = %q", report.Framework)
	}
}

func TestGenerateReport_HIPAA(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "hipaa"})
	if err != nil {
		t.Fatal(err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
	if report.Framework != "hipaa" {
		t.Errorf("framework = %q", report.Framework)
	}
}

func TestGenerateReport_NIST(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "nist_sp_800-53"})
	if err != nil {
		t.Fatal(err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
}

func TestGenerateReport_SOC2(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "soc_2"})
	if err != nil {
		t.Fatal(err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
}

func TestGenerateReport_CIS(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "cis_csc_v8"})
	if err != nil {
		t.Fatal(err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
}

func TestGenerateReport_ISO27001(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "iso_27001-2013"})
	if err != nil {
		t.Fatal(err)
	}
	if report == nil {
		t.Fatal("expected report")
	}
}

func TestReportRenderText(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, _ := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	s := report.RenderText()
	if s == "" {
		t.Fatal("expected non-empty string")
	}
	if !strings.Contains(s, "Score") {
		t.Logf("report text: %s", s[:min(200, len(s))])
		t.Error("expected Score in report")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestReportResults(t *testing.T) {
	e := NewReportEngine(&mockSCA{})
	report, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Results == nil {
		t.Fatal("expected results in report")
	}
	for _, r := range report.Results {
		if r.ID == "" {
			t.Error("expected control ID in result")
		}
	}
}

func TestScoreTracking(t *testing.T) {
	points := []ScorePoint{
		{Date: "2026-01-01", Score: 85, Total: 100, Passed: 85, Failed: 15},
		{Date: "2026-01-08", Score: 90, Total: 100, Passed: 90, Failed: 10},
	}
	if points[1].Score > points[0].Score {
		// Score improved — valid
	}
}

func TestEvidence(t *testing.T) {
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
