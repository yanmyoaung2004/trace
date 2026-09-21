package cases

import (
	"context"
	"strings"
	"testing"
)

func TestExportCSV_IOCsAndEvents(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	c, err := m.Create(ctx, "CSV case", "desc", "high")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddIOC(ctx, c.ID, "ip", "10.0.0.5", "c2 server"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddEvent(ctx, c.ID, "note", "analyst, reviewed \"carefully\"", "manual"); err != nil {
		t.Fatal(err)
	}

	out, err := m.ExportCSV(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if lines[0] != "section,type,value,description,source,created_at" {
		t.Errorf("header = %q", lines[0])
	}
	if len(lines) != 3 {
		t.Fatalf("rows = %d, want 2 + header:\n%s", len(lines)-1, out)
	}
	if !strings.HasPrefix(lines[1], "ioc,ip,10.0.0.5,c2 server,") {
		t.Errorf("ioc row = %q", lines[1])
	}
	// Comma + quotes in event content must be CSV-escaped.
	if !strings.Contains(lines[2], `"analyst, reviewed ""carefully"""`) {
		t.Errorf("event row not escaped: %q", lines[2])
	}
}

func TestExportCEF_Shape(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	c, err := m.Create(ctx, "CEF case", "", "critical")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddIOC(ctx, c.ID, "domain", "evil.example", "phish"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddEvent(ctx, c.ID, "note", "escalated", "manual"); err != nil {
		t.Fatal(err)
	}

	out, err := m.ExportCEF(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("events = %d, want 1 ioc + 1 event:\n%s", len(lines), out)
	}
	for _, ln := range lines {
		if !strings.HasPrefix(ln, "CEF:0|Trace|Case|1.0|") {
			t.Errorf("missing CEF prefix: %q", ln)
		}
		if !strings.Contains(ln, "caseId="+c.ID) {
			t.Errorf("missing caseId: %q", ln)
		}
		if !strings.Contains(ln, "|10|") {
			t.Errorf("critical case should map to severity 10: %q", ln)
		}
	}
	if !strings.Contains(lines[0], "evil.example") {
		t.Errorf("ioc value missing: %q", lines[0])
	}
}

func TestExport_UnknownCase(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	if _, err := m.ExportCSV(ctx, "nope"); err == nil {
		t.Error("ExportCSV: expected error for unknown case")
	}
	if _, err := m.ExportCEF(ctx, "nope"); err == nil {
		t.Error("ExportCEF: expected error for unknown case")
	}
}
