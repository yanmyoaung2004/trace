package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type ReportOptions struct {
	Framework string
	Output    string
	Format    string
	PolicyName string
}

type Engine struct {
	scaAgent agent.Agent
}

func NewEngine(sca agent.Agent) *Engine {
	return &Engine{scaAgent: sca}
}

type Report struct {
	GeneratedAt string
	Framework   string
	Score       float64
	Total       int
	Passed      int
	Failed      int
	NotCovered  int
	Results     []ControlReport
}

type ControlReport struct {
	ID      string
	Title   string
	Status  string
	Passed  int
	Failed  int
	Total   int
	Details []CheckDetail
}

type CheckDetail struct {
	CheckID     int
	Title       string
	PolicyID    string
	PolicyName  string
	Status      string
	Remediation string
}

func (e *Engine) GenerateReport(ctx context.Context, opts ReportOptions) (*Report, error) {
	framework, ok := Frameworks[opts.Framework]
	if !ok {
		return nil, fmt.Errorf("unknown framework: %s (supported: %s)", opts.Framework, supportedFrameworks())
	}

	input := agent.Input{"action": "scan_system"}
	if opts.PolicyName != "" {
		input["action"] = "run_policy"
		input["policy_name"] = opts.PolicyName
	}

	output, err := e.scaAgent.Execute(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	resultsRaw, _ := output["results"].([]any)
	var checkResults []ComplianceCheckResult
	for _, r := range resultsRaw {
		if m, ok := r.(map[string]any); ok {
			complianceRaw, _ := m["compliance"].(map[string]any)
			compliance := make(map[string][]string)
			for k, v := range complianceRaw {
				switch val := v.(type) {
				case []any:
					for _, item := range val {
						if s, ok := item.(string); ok {
							compliance[k] = append(compliance[k], s)
						}
					}
				case string:
					compliance[k] = []string{val}
				}
			}
			cr := ComplianceCheckResult{
				CheckID:     int(toFloat64(m["id"])),
				Title:       toString(m["title"]),
				Status:      toString(m["status"]),
				Remediation: toString(m["remediation"]),
				Compliance:  compliance,
			}
			checkResults = append(checkResults, cr)
		}
	}

	report := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Framework:   opts.Framework,
	}

	totalControls := len(framework.Controls)
	for _, c := range framework.Controls {
		cr := ControlReport{ID: c.ID, Title: c.Title}
		for _, ch := range checkResults {
			if ids, ok := ch.Compliance[opts.Framework]; ok {
				for _, id := range ids {
					if id == c.ID {
						cr.Total++
						cr.Details = append(cr.Details, CheckDetail{
							CheckID:     ch.CheckID,
							Title:       ch.Title,
							Status:      ch.Status,
							Remediation: ch.Remediation,
						})
						if ch.Status == "pass" {
							cr.Passed++
						} else {
							cr.Failed++
						}
					}
				}
			}
		}
		if cr.Total > 0 {
			if cr.Failed == 0 {
				cr.Status = "pass"
				report.Passed++
			} else {
				cr.Status = "fail"
				report.Failed++
			}
		} else {
			cr.Status = "not-covered"
			report.NotCovered++
		}
		report.Results = append(report.Results, cr)
	}

	report.Total = totalControls
	if totalControls > 0 {
		report.Score = float64(report.Passed) / float64(totalControls) * 100
	}

	return report, nil
}

func (r *Report) RenderText() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Framework: %s\n", r.Framework))
	b.WriteString(fmt.Sprintf("Generated: %s\n", r.GeneratedAt))
	b.WriteString(fmt.Sprintf("Score: %.0f%% (%d/%d controls passed)\n\n", r.Score, r.Passed, r.Total))
	b.WriteString(fmt.Sprintf("Passed: %d | Failed: %d | Not covered: %d\n\n", r.Passed, r.Failed, r.NotCovered))

	w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Control\tTitle\tStatus\tChecks Passed/Failed")
	fmt.Fprintln(w, "-------\t-----\t------\t-------------------")
	for _, cr := range r.Results {
		status := "❌"
		switch cr.Status {
		case "pass":
			status = "✅"
		case "fail":
			status = "⚠️"
		case "not-covered":
			status = "—"
		}
		ratio := fmt.Sprintf("%d/%d", cr.Passed, cr.Total)
		if cr.Total == 0 {
			ratio = "0/0"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", cr.ID, cr.Title, status, ratio)
	}
	w.Flush()
	return b.String()
}

func (r *Report) RenderHTML() string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Compliance Report</title>")
	b.WriteString("<style>")
	b.WriteString("body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#e0e0e0;padding:24px}")
	b.WriteString("h1{color:#00BFFF}h2{color:#708090}")
	b.WriteString("table{width:100%;border-collapse:collapse}")
	b.WriteString("th{background:#0f3460;padding:10px 14px;text-align:left;color:#e0e0e0}")
	b.WriteString("td{padding:10px 14px;border-bottom:1px solid #0f3460}")
	b.WriteString(".pass{color:#32CD32}.fail{color:#FF4444}.na{color:#666}")
	b.WriteString(".score{font-size:48px;font-weight:bold}.good{color:#32CD32}.bad{color:#FF4444}")
	b.WriteString("</style></head><body>")
	b.WriteString(fmt.Sprintf("<h1>Compliance Report: %s</h1>", r.Framework))
	b.WriteString(fmt.Sprintf("<p>Generated: %s</p>", r.GeneratedAt))
	scoreClass := "good"
	if r.Score < 60 {
		scoreClass = "bad"
	}
	b.WriteString(fmt.Sprintf("<div class='score %s'>%.0f%%</div>", scoreClass, r.Score))
	b.WriteString(fmt.Sprintf("<p>%d/%d controls passed. %d failed. %d not covered.</p>", r.Passed, r.Total, r.Failed, r.NotCovered))
	b.WriteString("<table><thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Checks</th></tr></thead><tbody>")
	for _, cr := range r.Results {
		statusClass := "na"
		statusLabel := "Not covered"
		switch cr.Status {
		case "pass":
			statusClass = "pass"
			statusLabel = "Pass"
		case "fail":
			statusClass = "fail"
			statusLabel = fmt.Sprintf("Fail (%d/%d)", cr.Failed, cr.Total)
		}
		ratio := fmt.Sprintf("%d/%d", cr.Passed, cr.Total)
		if cr.Total == 0 {
			ratio = "-"
		}
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%s</td></tr>",
			cr.ID, cr.Title, statusClass, statusLabel, ratio))
	}
	b.WriteString("</tbody></table></body></html>")
	return b.String()
}

func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Compliance Report: %s\n\n", r.Framework))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", r.GeneratedAt))
	b.WriteString(fmt.Sprintf("**Score:** %.0f%% (%d/%d)\n\n", r.Score, r.Passed, r.Total))

	b.WriteString("| Control | Title | Status | Checks |\n")
	b.WriteString("|---------|-------|--------|--------|\n")
	for _, cr := range r.Results {
		status := "❌ Not covered"
		switch cr.Status {
		case "pass":
			status = "✅ Pass"
		case "fail":
			status = fmt.Sprintf("⚠️ Fail (%d/%d)", cr.Failed, cr.Total)
		}
		ratio := fmt.Sprintf("%d/%d", cr.Passed, cr.Total)
		if cr.Total == 0 {
			ratio = "-"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", cr.ID, cr.Title, status, ratio))
	}
	return b.String()
}

func (r *Report) RenderJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *Report) WriteFile(path string) error {
	var data []byte
	if strings.HasSuffix(path, ".html") {
		data = []byte(r.RenderHTML())
	} else if strings.HasSuffix(path, ".md") {
		data = []byte(r.RenderMarkdown())
	} else if strings.HasSuffix(path, ".json") {
		js, err := r.RenderJSON()
		if err != nil {
			return err
		}
		data = []byte(js)
	} else if strings.HasSuffix(path, ".txt") {
		data = []byte(r.RenderText())
	} else {
		// Try to infer format from framework name
		data = []byte(r.RenderMarkdown())
	}
	return os.WriteFile(path, data, 0644)
}

func (r *Report) Bytes(format string) []byte {
	switch format {
	case "html":
		return []byte(r.RenderHTML())
	case "json":
		s, _ := r.RenderJSON()
		return []byte(s)
	case "txt":
		return []byte(r.RenderText())
	default:
		return []byte(r.RenderMarkdown())
	}
}

type reportSummary struct {
	Controls []controlSummary `json:"controls"`
}

type controlSummary struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Passed  bool   `json:"passed"`
	Score   int    `json:"score"`
}

func toFloat64(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case json.Number:
		f, _ := val.Float64()
		return f
	}
	return 0
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func RenderReportToWriter(ctx context.Context, report *Report, format string, writer *bytes.Buffer) {
	if format == "html" {
		writer.WriteString(report.RenderHTML())
	} else if format == "json" {
		s, _ := report.RenderJSON()
		writer.WriteString(s)
	} else {
		writer.WriteString(report.RenderText())
	}
}

func init() {
	_ = bytes.NewBuffer
}
