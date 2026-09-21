package cases

import (
	"context"
	"fmt"
	"strings"
)

// CSV/CEF exports alongside the existing ExportHTML/ExportPDF.
// Read-only: SELECTs via the existing Manager helpers, no schema changes.

func casesCSVField(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func casesCEFToken(s string) string {
	r := strings.NewReplacer("|", "_", "\\", "_", "=", "_", "\n", " ", "\r", " ")
	return r.Replace(strings.TrimSpace(s))
}

func caseCEFSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "low":
		return 3
	case "medium":
		return 5
	case "high":
		return 8
	case "critical":
		return 10
	default:
		return 5
	}
}

// ExportCSV renders a case's IOCs and timeline events as CSV.
func (m *Manager) ExportCSV(ctx context.Context, id string) (string, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return "", err
	}
	iocs, err := m.GetIOCs(ctx, c.ID)
	if err != nil {
		return "", err
	}
	events, err := m.GetEvents(ctx, c.ID)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("section,type,value,description,source,created_at\n")
	for _, i := range iocs {
		b.WriteString(fmt.Sprintf("ioc,%s,%s,%s,%s,%s\n",
			casesCSVField(i.IOCType), casesCSVField(i.Value),
			casesCSVField(i.Description), casesCSVField(i.Source),
			casesCSVField(i.CreatedAt)))
	}
	for _, e := range events {
		b.WriteString(fmt.Sprintf("event,%s,%s,%s,%s,%s\n",
			casesCSVField(e.EventType), casesCSVField(e.Content),
			"", casesCSVField(e.Source), casesCSVField(e.CreatedAt)))
	}
	return b.String(), nil
}

// ExportCEF renders one CEF event per IOC plus one per timeline event so
// cases can be forwarded to a SIEM next to detections.
func (m *Manager) ExportCEF(ctx context.Context, id string) (string, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return "", err
	}
	iocs, err := m.GetIOCs(ctx, c.ID)
	if err != nil {
		return "", err
	}
	events, err := m.GetEvents(ctx, c.ID)
	if err != nil {
		return "", err
	}
	sev := caseCEFSeverity(c.Severity)
	var b strings.Builder
	for _, i := range iocs {
		// CEF:Version|Vendor|Product|Ver|Signature|Name|Severity|Extension
		b.WriteString(fmt.Sprintf("CEF:0|Trace|Case|1.0|%s|%s|%d|caseId=%s iocType=%s iocValue=%s source=%s\n",
			casesCEFToken("ioc-"+i.IOCType),
			casesCEFToken(i.Value),
			sev,
			casesCEFToken(c.ID),
			casesCEFToken(i.IOCType),
			casesCEFToken(i.Value),
			casesCEFToken(i.Source)))
	}
	for _, e := range events {
		b.WriteString(fmt.Sprintf("CEF:0|Trace|Case|1.0|%s|%s|%d|caseId=%s eventType=%s source=%s\n",
			casesCEFToken("event-"+e.EventType),
			casesCEFToken(e.EventType),
			sev,
			casesCEFToken(c.ID),
			casesCEFToken(e.EventType),
			casesCEFToken(e.Source)))
	}
	return b.String(), nil
}
