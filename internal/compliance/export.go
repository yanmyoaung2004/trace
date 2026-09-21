package compliance

import (
	"fmt"
	"strings"
)

// RenderCSV renders the report as CSV (one row per control).
// New additive renderer: existing HTML/PDF/JSON/Markdown paths untouched.
func (r *Report) RenderCSV() string {
	var b strings.Builder
	b.WriteString("control,title,status,passed,failed,total\n")
	for _, cr := range r.Results {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%d,%d,%d\n",
			csvField(cr.ID), csvField(cr.Title), cr.Status,
			cr.Passed, cr.Failed, cr.Total))
	}
	return b.String()
}

func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// RenderCEF renders one CEF event per failed control so SIEMs can ingest
// compliance drift alongside detections. Pass-only reports yield an empty
// string (no findings to forward).
func (r *Report) RenderCEF() string {
	var b strings.Builder
	for _, cr := range r.Results {
		if cr.Status != "fail" {
			continue
		}
		// CEF:Version|Vendor|Product|Ver|Signature|Name|Severity|Extension
		b.WriteString(fmt.Sprintf("CEF:0|Trace|Compliance|1.0|%s|%s|5|framework=%s passed=%d failed=%d total=%d\n",
			cefToken(cr.ID+"-fail"),
			cefToken(cr.Title),
			cefToken(r.Framework),
			cr.Passed, cr.Failed, cr.Total))
	}
	return b.String()
}

func cefToken(s string) string {
	r := strings.NewReplacer("|", "_", "\\", "_", "=", "_", "\n", " ", "\r", " ")
	return r.Replace(strings.TrimSpace(s))
}

// RenderFormat dispatches text|markdown|html|json|csv|cef without touching
// the legacy Bytes/WriteFile paths.
func (r *Report) RenderFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return r.RenderText(), nil
	case "markdown", "md":
		return r.RenderMarkdown(), nil
	case "html":
		return r.RenderHTML(), nil
	case "json":
		return r.RenderJSON()
	case "csv":
		return r.RenderCSV(), nil
	case "cef":
		return r.RenderCEF(), nil
	default:
		return "", fmt.Errorf("unknown report format: %q (want text|markdown|html|json|csv|cef)", format)
	}
}
