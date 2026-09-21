package compliance

import (
	"context"
	"strings"
	"testing"
)

func mustReport(t *testing.T) *Report {
	t.Helper()
	e := newTestEngine(t)
	r, err := e.GenerateReport(context.Background(), ReportOptions{Framework: "pci_dss_v4.0"})
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	return r
}

func TestRenderCSV_HeaderAndRows(t *testing.T) {
	r := mustReport(t)
	csv := r.RenderCSV()
	lines := strings.Split(strings.TrimRight(csv, "\n"), "\n")
	if lines[0] != "control,title,status,passed,failed,total" {
		t.Errorf("header = %q", lines[0])
	}
	if len(lines) != len(r.Results)+1 {
		t.Errorf("rows = %d, want %d + header", len(lines)-1, len(r.Results))
	}
	// Every control ID must appear exactly once.
	for _, cr := range r.Results {
		found := false
		for _, ln := range lines[1:] {
			if strings.HasPrefix(ln, cr.ID+",") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("control %q missing from CSV", cr.ID)
		}
	}
}

func TestRenderCSV_EscapesCommas(t *testing.T) {
	r := &Report{Framework: "x", Results: []ControlReport{
		{ID: "1", Title: `a, "quoted" title`, Status: "fail"},
	}}
	csv := r.RenderCSV()
	if !strings.Contains(csv, `"a, ""quoted"" title"`) {
		t.Errorf("CSV escaping wrong:\n%s", csv)
	}
}

func TestRenderCEF_OnlyFailures(t *testing.T) {
	r := &Report{Framework: "pci_dss_v4.0", Results: []ControlReport{
		{ID: "1.1", Title: "Pass control", Status: "pass"},
		{ID: "4.1", Title: "Fail control", Status: "fail", Failed: 1, Total: 1},
	}}
	cef := r.RenderCEF()
	if strings.Contains(cef, "Pass control") {
		t.Errorf("CEF must not include passing controls:\n%s", cef)
	}
	if !strings.Contains(cef, "CEF:0|Trace|Compliance|1.0|") {
		t.Errorf("CEF prefix missing:\n%s", cef)
	}
	if !strings.Contains(cef, "framework=pci_dss_v4.0") {
		t.Errorf("CEF framework extension missing:\n%s", cef)
	}
}

func TestRenderCEF_EmptyWhenAllPass(t *testing.T) {
	r := &Report{Framework: "x", Results: []ControlReport{
		{ID: "1", Title: "ok", Status: "pass"},
	}}
	if got := r.RenderCEF(); got != "" {
		t.Errorf("expected empty CEF, got %q", got)
	}
}

func TestRenderFormat_Dispatch(t *testing.T) {
	r := mustReport(t)
	for _, f := range []string{"text", "markdown", "html", "json", "csv", "cef"} {
		out, err := r.RenderFormat(f)
		if err != nil {
			t.Errorf("RenderFormat(%q): %v", f, err)
			continue
		}
		if f != "cef" && out == "" {
			t.Errorf("RenderFormat(%q) empty", f)
		}
	}
	if _, err := r.RenderFormat("pdf"); err == nil {
		t.Error("expected error for unknown format pdf")
	}
}

func TestScheduledReport_Validate(t *testing.T) {
	good := ScheduledReport{Name: "weekly-pci", Framework: "pci_dss_v4.0", Format: "csv", Interval: "168h"}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate(good): %v", err)
	}
	bad := []ScheduledReport{
		{Framework: "pci_dss_v4.0", Interval: "24h"},                  // no name
		{Name: "x", Framework: "nope", Interval: "24h"},               // bad framework
		{Name: "x", Framework: "pci_dss_v4.0", Format: "pdf"},         // bad format, no interval path matters
		{Name: "x", Framework: "pci_dss_v4.0", Interval: ""},          // no interval
		{Name: "x", Framework: "pci_dss_v4.0", Interval: "fortnight"}, // bad duration
	}
	for i, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestRunScheduled_CSV(t *testing.T) {
	e := newTestEngine(t)
	out, err := e.RunScheduled(context.Background(), ScheduledReport{
		Name: "nightly", Framework: "pci_dss_v4.0", Format: "csv", Interval: "24h",
	})
	if err != nil {
		t.Fatalf("RunScheduled: %v", err)
	}
	if !strings.HasPrefix(out, "control,title,status,passed,failed,total\n") {
		t.Errorf("scheduled CSV missing header:\n%s", out[:min(200, len(out))])
	}
}

func TestRunScheduled_RejectsBadSchedule(t *testing.T) {
	e := newTestEngine(t)
	_, err := e.RunScheduled(context.Background(), ScheduledReport{Name: "bad"})
	if err == nil {
		t.Error("expected error for invalid schedule")
	}
}
