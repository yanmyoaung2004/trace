package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type ReportOptions struct {
	Framework string
	Output    string
	Format    string
	Force     bool
}

type Evidence struct {
	ID          string `json:"id"`
	ControlID   string `json:"control_id"`
	Framework   string `json:"framework"`
	Description string `json:"description"`
	FilePath    string `json:"file_path"`
	Content     string `json:"content,omitempty"`
	Status      string `json:"status"`
	Assessor    string `json:"assessor"`
	CreatedAt   string `json:"created_at"`
}

type ManualAssessment struct {
	ControlID   string `json:"control_id"`
	Framework   string `json:"framework"`
	Status      string `json:"status"` // pass, fail, not-applicable
	Justification string `json:"justification"`
	Assessor    string `json:"assessor"`
	Timestamp   string `json:"timestamp"`
}

type ReportEngine struct {
	SCAAgent    agent.Agent
	Assessments []ManualAssessment
	Evidences   []Evidence
	DataDir     string
}

func NewReportEngine(scaAgent agent.Agent) *ReportEngine {
	home, _ := os.UserHomeDir()
	return &ReportEngine{
		SCAAgent: scaAgent,
		DataDir:  filepath.Join(home, ".trace", "compliance"),
	}
}

func (e *ReportEngine) GenerateReport(ctx context.Context, opts ReportOptions) (*Report, error) {
	fw, ok := Frameworks[opts.Framework]
	if !ok {
		return nil, fmt.Errorf("unknown framework: %s", opts.Framework)
	}

	report := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Framework:   opts.Framework,
		Total:       len(fw.Controls),
	}

	for _, c := range fw.Controls {
		cr := ControlReport{
			ID:    c.ID,
			Title: c.Title,
		}

		if ma, err := e.getManualAssessment(opts.Framework, c.ID); err == nil {
			cr.Status = ma.Status
			if ma.Status == "pass" {
				cr.Passed = 1
			} else {
				cr.Failed = 1
			}
			cr.Total = 1
			cr.Details = append(cr.Details, CheckDetail{
				Status:      ma.Status,
				Remediation: ma.Justification,
			})
		}

		if evs := e.getEvidence(opts.Framework, c.ID); len(evs) > 0 {
			for _, ev := range evs {
				cr.Details = append(cr.Details, CheckDetail{
					Status: ev.Status,
					Title:  ev.Description,
				})
			}
		}

		if cr.Total == 0 {
			cr.Status = "not-covered"
			report.NotCovered++
		} else if cr.Failed == 0 && cr.Passed > 0 {
			cr.Status = "pass"
			report.Passed++
		} else {
			cr.Status = "fail"
			report.Failed++
		}

		report.Results = append(report.Results, cr)
	}

	if report.Total > 0 {
		report.Score = float64(report.Passed) / float64(report.Total) * 100
	}

	if err := e.tryAutoScan(ctx, opts); err == nil {
		e.mergeScanResults(report)
	}

	return report, nil
}

func (e *ReportEngine) tryAutoScan(ctx context.Context, opts ReportOptions) error {
	input := agent.Input{
		"action": "scan_system",
	}
	if opts.Force {
		input["action"] = "list_policies"
	}

	output, err := e.SCAAgent.Execute(ctx, input)
	if err != nil {
		return err
	}

	if errStr, _ := output["error"].(string); errStr != "" {
		return fmt.Errorf("%s", errStr)
	}

	return e.parseSCAResults(output)
}

func (e *ReportEngine) parseSCAResults(output map[string]any) error {
	resultsRaw, _ := output["results"].([]any)
	for _, r := range resultsRaw {
		if m, ok := r.(map[string]any); ok {
			complianceRaw, _ := m["compliance"].(map[string]any)
			for fw, ids := range complianceRaw {
				fwName := strings.ReplaceAll(fw, "_", "-")
				if _, exists := Frameworks[fw]; !exists {
					continue
				}
				_ = fwName
				checkStatus, _ := m["status"].(string)
				checkTitle, _ := m["title"].(string)
				checkID := m["id"]
				_ = checkID
				_ = checkTitle
				_ = checkStatus
				_ = ids
			}
		}
	}
	return nil
}

func (e *ReportEngine) mergeScanResults(report *Report) {
}

func (e *ReportEngine) getManualAssessment(framework, controlID string) (ManualAssessment, error) {
	e.loadAssessments()
	for _, a := range e.Assessments {
		if a.Framework == framework && a.ControlID == controlID {
			return a, nil
		}
	}
	return ManualAssessment{}, fmt.Errorf("not found")
}

func (e *ReportEngine) SetManualAssessment(ctx context.Context, framework, controlID, status, justification string) error {
	os.MkdirAll(e.DataDir, 0755)
	e.loadAssessments()

	for i, a := range e.Assessments {
		if a.Framework == framework && a.ControlID == controlID {
			e.Assessments[i].Status = status
			e.Assessments[i].Justification = justification
			e.Assessments[i].Timestamp = time.Now().UTC().Format(time.RFC3339)
			return e.saveAssessments()
		}
	}

	e.Assessments = append(e.Assessments, ManualAssessment{
		ControlID:     controlID,
		Framework:     framework,
		Status:        status,
		Justification: justification,
		Assessor:      "cli",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	})
	return e.saveAssessments()
}

func (e *ReportEngine) AddEvidence(ctx context.Context, framework, controlID, description, filePath string) error {
	os.MkdirAll(e.DataDir, 0754)
	e.loadEvidences()

	content := ""
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err == nil {
			content = string(data)
		}
	}

	e.Evidences = append(e.Evidences, Evidence{
		ID:          fmt.Sprintf("ev-%d", len(e.Evidences)+1),
		ControlID:   controlID,
		Framework:   framework,
		Description: description,
		FilePath:    filePath,
		Content:     content,
		Assessor:    "cli",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	})
	return e.saveEvidences()
}

func (e *ReportEngine) getEvidence(framework, controlID string) []Evidence {
	e.loadEvidences()
	var out []Evidence
	for _, ev := range e.Evidences {
		if ev.Framework == framework && ev.ControlID == controlID {
			out = append(out, ev)
		}
	}
	return out
}

func (e *ReportEngine) loadAssessments() {
	path := filepath.Join(e.DataDir, "assessments.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	json.Unmarshal(data, &e.Assessments)
}

func (e *ReportEngine) saveAssessments() error {
	path := filepath.Join(e.DataDir, "assessments.json")
	data, _ := json.MarshalIndent(e.Assessments, "", "  ")
	return os.WriteFile(path, data, 0644)
}

func (e *ReportEngine) loadEvidences() {
	path := filepath.Join(e.DataDir, "evidences.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	json.Unmarshal(data, &e.Evidences)
}

func (e *ReportEngine) saveEvidences() error {
	path := filepath.Join(e.DataDir, "evidences.json")
	data, _ := json.MarshalIndent(e.Evidences, "", "  ")
	return os.WriteFile(path, data, 0644)
}

type Report struct {
	GeneratedAt string          `json:"generated_at"`
	Framework   string          `json:"framework"`
	Score       float64         `json:"score"`
	Total       int             `json:"total"`
	Passed      int             `json:"passed"`
	Failed      int             `json:"failed"`
	NotCovered  int             `json:"not_covered"`
	Results     []ControlReport `json:"results"`
}

type ControlReport struct {
	ID      string        `json:"id"`
	Title   string        `json:"title"`
	Status  string        `json:"status"`
	Passed  int           `json:"passed"`
	Failed  int           `json:"failed"`
	Total   int           `json:"total"`
	Details []CheckDetail `json:"details,omitempty"`
}

type CheckDetail struct {
	CheckID     int    `json:"check_id,omitempty"`
	Title       string `json:"title,omitempty"`
	Status      string `json:"status"`
	Remediation string `json:"remediation,omitempty"`
}

func (r *Report) RenderText() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Framework: %s\n", r.Framework))
	b.WriteString(fmt.Sprintf("Generated: %s\n", r.GeneratedAt))
	b.WriteString(fmt.Sprintf("Score: %.0f%% (%d/%d controls passed)\n\n", r.Score, r.Passed, r.Total))
	b.WriteString(fmt.Sprintf("Passed: %d | Failed: %d | Not covered: %d\n\n", r.Passed, r.Failed, r.NotCovered))

	w := tabwriter.NewWriter(&b, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Control\tTitle\tStatus\tDetails")
	fmt.Fprintln(w, "-------\t-----\t------\t-------")
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
		details := "-"
		if len(cr.Details) > 0 {
			details = cr.Details[0].Status
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", cr.ID, cr.Title, status, details)
	}
	w.Flush()
	return b.String()
}

func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Compliance Report: %s\n\n", r.Framework))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n", r.GeneratedAt))
	b.WriteString(fmt.Sprintf("**Score:** %.0f%% (%d/%d)\n\n", r.Score, r.Passed, r.Total))

	b.WriteString("| Control | Title | Status | Details |\n")
	b.WriteString("|---------|-------|--------|--------|\n")
	for _, cr := range r.Results {
		status := "❌ Not covered"
		switch cr.Status {
		case "pass":
			status = "✅ Pass"
		case "fail":
			status = "⚠️ Fail"
		}
		details := "-"
		if len(cr.Details) > 0 {
			details = cr.Details[0].Status
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", cr.ID, cr.Title, status, details))
	}
	return b.String()
}

func (r *Report) RenderHTML() string {
	var b strings.Builder
	b.WriteString("<html><head><meta charset='utf-8'><title>Compliance Report</title><style>")
	b.WriteString("body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#e0e0e0;padding:24px}")
	b.WriteString("h1{color:#00BFFF}table{width:100%;border-collapse:collapse}")
	b.WriteString("th{background:#0f3460;padding:10px;text-align:left;color:#e0e0e0}")
	b.WriteString("td{padding:10px;border-bottom:1px solid #0f3460}")
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
	b.WriteString("<table><thead><tr><th>Control</th><th>Title</th><th>Status</th></tr></thead><tbody>")
	for _, cr := range r.Results {
		cls := "na"
		label := "Not covered"
		switch cr.Status {
		case "pass":
			cls = "pass"
			label = "Pass"
		case "fail":
			cls = "fail"
			label = "Fail"
		}
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td class='%s'>%s</td></tr>", cr.ID, cr.Title, cls, label))
	}
	b.WriteString("</tbody></table></body></html>")
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
	switch {
	case strings.HasSuffix(path, ".html"):
		data = []byte(r.RenderHTML())
	case strings.HasSuffix(path, ".md"):
		data = []byte(r.RenderMarkdown())
	case strings.HasSuffix(path, ".json"):
		s, _ := r.RenderJSON()
		data = []byte(s)
	default:
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
	default:
		return []byte(r.RenderMarkdown())
	}
}

func init() {
	_ = bytes.NewBuffer
}
