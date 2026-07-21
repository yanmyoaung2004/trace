package cases

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jung-kurt/gofpdf/v2"
	"github.com/yanmyoaung2004/trace/internal/db"
)

type Case struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Severity    string   `json:"severity"`
	Assignee    string   `json:"assignee,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Resolution  string   `json:"resolution,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	ClosedAt    *string  `json:"closed_at,omitempty"`
}

type Event struct {
	ID        string `json:"id"`
	CaseID    string `json:"case_id"`
	EventType string `json:"event_type"`
	Content   string `json:"content"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

type IOC struct {
	ID          string `json:"id"`
	CaseID      string `json:"case_id"`
	IOCType     string `json:"ioc_type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
	CreatedAt   string `json:"created_at"`
}

type Manager struct {
	db *db.DB
}

func NewManager(database *db.DB) *Manager {
	return &Manager{db: database}
}

func (m *Manager) Create(ctx context.Context, title, description, severity string) (*Case, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id := uuid.New().String()

	if severity == "" {
		severity = "medium"
	}
	status := "open"

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO cases (id, title, description, status, severity, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, title, description, status, severity, now, now)
	if err != nil {
		return nil, fmt.Errorf("create case: %w", err)
	}

	c, err := m.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get created case: %w", err)
	}
	return c, nil
}

func (m *Manager) Get(ctx context.Context, id string) (*Case, error) {
	c := &Case{}
	var tagsJSON, closed, assignee sql.NullString
	err := m.db.QueryRowContext(ctx,
		`SELECT id, title, description, status, severity, assignee, tags, resolution, created_at, updated_at, closed_at FROM cases WHERE id = ?`, id).
		Scan(&c.ID, &c.Title, &c.Description, &c.Status, &c.Severity, &assignee, &tagsJSON, &c.Resolution, &c.CreatedAt, &c.UpdatedAt, &closed)
	if err != nil {
		return nil, fmt.Errorf("get case: %w", err)
	}
	if assignee.Valid {
		c.Assignee = assignee.String
	}
	if tagsJSON.Valid {
		json.Unmarshal([]byte(tagsJSON.String), &c.Tags)
	}
	if closed.Valid {
		c.ClosedAt = &closed.String
	}
	return c, nil
}

func (m *Manager) List(ctx context.Context, status, severity string) ([]*Case, error) {
	query := `SELECT id FROM cases WHERE 1=1`
	var args []any
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	if severity != "" {
		query += ` AND severity = ?`
		args = append(args, severity)
	}
	query += ` ORDER BY created_at DESC LIMIT 100`

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cases []*Case
	for rows.Next() {
		var id string
		rows.Scan(&id)
		c, err := m.Get(ctx, id)
		if err != nil {
			continue
		}
		cases = append(cases, c)
	}
	return cases, nil
}

func (m *Manager) UpdateStatus(ctx context.Context, id, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	q := `UPDATE cases SET status = ?, updated_at = ?`
	if status == "closed" || status == "resolved" {
		q += `, closed_at = ?`
	}
	q += ` WHERE id = ?`

	var err error
	if status == "closed" || status == "resolved" {
		_, err = m.db.ExecContext(ctx, q, status, now, now, id)
	} else {
		_, err = m.db.ExecContext(ctx, q, status, now, id)
	}
	return err
}

func (m *Manager) Assign(ctx context.Context, id, assignee string) error {
	_, err := m.db.ExecContext(ctx,
		`UPDATE cases SET assignee = ?, updated_at = datetime('now') WHERE id = ?`, assignee, id)
	return err
}

func (m *Manager) Resolve(ctx context.Context, id, resolution string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := m.db.ExecContext(ctx,
		`UPDATE cases SET status = 'resolved', resolution = ?, closed_at = ?, updated_at = ? WHERE id = ?`,
		resolution, now, now, id)
	return err
}

func (m *Manager) AddEvent(ctx context.Context, caseID, eventType, content, source string) (*Event, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id := uuid.New().String()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO case_events (id, case_id, event_type, content, source, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, caseID, eventType, content, source, now)
	if err != nil {
		return nil, err
	}
	return &Event{ID: id, CaseID: caseID, EventType: eventType, Content: content, Source: source, CreatedAt: now}, nil
}

func (m *Manager) GetEvents(ctx context.Context, caseID string) ([]*Event, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, case_id, event_type, content, source, created_at FROM case_events WHERE case_id = ? ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e := &Event{}
		if err := rows.Scan(&e.ID, &e.CaseID, &e.EventType, &e.Content, &e.Source, &e.CreatedAt); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, nil
}

func (m *Manager) AddIOC(ctx context.Context, caseID, iocType, value, description string) (*IOC, error) {
	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	iocType = strings.ToLower(iocType)
	switch iocType {
	case "ip", "ipv4", "ipv6":
		iocType = "ip"
	case "domain":
	case "url":
	case "hash", "md5", "sha1", "sha256":
		iocType = "hash"
	case "email":
	case "file", "path":
		iocType = "filepath"
	default:
		iocType = "unknown"
	}

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO case_iocs (id, case_id, ioc_type, value, description, source, created_at) VALUES (?, ?, ?, ?, ?, 'manual', ?)`,
		id, caseID, iocType, value, description, now)
	if err != nil {
		return nil, err
	}
	return &IOC{ID: id, CaseID: caseID, IOCType: iocType, Value: value, Description: description, CreatedAt: now}, nil
}

func (m *Manager) GetIOCs(ctx context.Context, caseID string) ([]*IOC, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, case_id, ioc_type, value, description, source, created_at FROM case_iocs WHERE case_id = ? ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var iocs []*IOC
	for rows.Next() {
		i := &IOC{}
		if err := rows.Scan(&i.ID, &i.CaseID, &i.IOCType, &i.Value, &i.Description, &i.Source, &i.CreatedAt); err != nil {
			continue
		}
		iocs = append(iocs, i)
	}
	return iocs, nil
}

func (m *Manager) ExportHTML(ctx context.Context, id string) (string, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return "", err
	}

	events, _ := m.GetEvents(ctx, id)
	iocs, _ := m.GetIOCs(ctx, id)

	severityColor := map[string]string{
		"low":      "var(--success)",
		"medium":   "var(--warning)",
		"high":     "var(--danger)",
		"critical": "oklch(0.65 0.22 30)",
	}

	sc := "#888"
	if s, ok := severityColor[c.Severity]; ok {
		sc = s
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Case Report: %s</title>
<style>
body { font-family: system-ui, sans-serif; padding: 40px; color: #222; line-height: 1.5; max-width: 800px; margin: 0 auto; }
h1 { font-size: 1.5em; margin-bottom: 4px; }
.meta { color: #666; font-size: 0.85em; margin-bottom: 24px; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 100px; font-size: 0.75em; font-weight: 600; }
.section { margin-top: 24px; }
.section h2 { font-size: 1.1em; border-bottom: 1px solid #ddd; padding-bottom: 6px; }
table { width: 100%%; border-collapse: collapse; font-size: 0.85em; }
th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #eee; }
th { color: #666; font-weight: 600; }
@media print { body { padding: 20px; } .no-print { display: none; } }
</style></head><body>
<div class="no-print" style="margin-bottom:16px"><a href="#" onclick="window.print()">Print / Save as PDF</a></div>
<h1 style="color:%s">[%s] %s</h1>
<div class="meta">Case ID: %s | Status: %s | Created: %s`, html.EscapeString(c.Title), sc, strings.ToUpper(c.Severity), html.EscapeString(c.Title), c.ID, c.Status, c.CreatedAt[:19]))

	if c.ClosedAt != nil {
		buf.WriteString(fmt.Sprintf(" | Closed: %s", (*c.ClosedAt)[:19]))
	}
	buf.WriteString("</div>")

	if c.Description != "" {
		buf.WriteString(fmt.Sprintf("<p>%s</p>", html.EscapeString(c.Description)))
	}

	if len(iocs) > 0 {
		buf.WriteString(`<div class="section"><h2>Indicators (%d)</h2><table><thead><tr><th>Type</th><th>Value</th><th>Description</th></tr></thead><tbody>`)
		for _, i := range iocs {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>`, html.EscapeString(i.IOCType), html.EscapeString(i.Value), html.EscapeString(i.Description)))
		}
		buf.WriteString("</tbody></table></div>")
	}

	if len(events) > 0 {
		buf.WriteString(`<div class="section"><h2>Timeline</h2><table><thead><tr><th>Time</th><th>Event</th><th>Details</th></tr></thead><tbody>`)
		for _, e := range events {
			buf.WriteString(fmt.Sprintf(`<tr><td style="white-space:nowrap">%s</td><td>%s</td><td>%s</td></tr>`, e.CreatedAt[:19], html.EscapeString(e.EventType), html.EscapeString(e.Content)))
		}
		buf.WriteString("</tbody></table></div>")
	}

	buf.WriteString(`<p style="color:#999;font-size:0.75em;margin-top:40px">Generated by Trace v0.2.0</p></body></html>`)
	return buf.String(), nil
}

func (m *Manager) ExportPDF(ctx context.Context, id string) ([]byte, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	events, _ := m.GetEvents(ctx, id)
	iocs, _ := m.GetIOCs(ctx, id)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.AddPage()

	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 12, "Security Case Report", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(0, 7, fmt.Sprintf("Case: %s", c.Title), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 5, fmt.Sprintf("ID: %s | Status: %s | Severity: %s", c.ID[:12], c.Status, c.Severity), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("Created: %s | Updated: %s", c.CreatedAt[:19], c.UpdatedAt[:19]), "", 1, "L", false, 0, "")
	if c.ClosedAt != nil {
		pdf.CellFormat(0, 5, fmt.Sprintf("Closed: %s", (*c.ClosedAt)[:19]), "", 1, "L", false, 0, "")
	}
	pdf.Ln(4)

	if c.Description != "" {
		pdf.SetFont("Helvetica", "I", 10)
		pdf.MultiCell(0, 5, c.Description, "", "L", false)
		pdf.Ln(4)
	}

	if len(iocs) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 8, fmt.Sprintf("Indicators (%d)", len(iocs)), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)

		pdf.SetFillColor(240, 240, 240)
		pdf.CellFormat(30, 6, "Type", "1", 0, "L", true, 0, "")
		pdf.CellFormat(60, 6, "Value", "1", 0, "L", true, 0, "")
		pdf.CellFormat(0, 6, "Description", "1", 1, "L", true, 0, "")

		for _, i := range iocs {
			pdf.CellFormat(30, 5, i.IOCType, "1", 0, "L", false, 0, "")
			pdf.CellFormat(60, 5, i.Value, "1", 0, "L", false, 0, "")
			pdf.CellFormat(0, 5, i.Description, "1", 1, "L", false, 0, "")
		}
		pdf.Ln(4)
	}

	if len(events) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 8, fmt.Sprintf("Timeline (%d events)", len(events)), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)

		pdf.SetFillColor(240, 240, 240)
		pdf.CellFormat(35, 5, "Time", "1", 0, "L", true, 0, "")
		pdf.CellFormat(25, 5, "Type", "1", 0, "L", true, 0, "")
		pdf.CellFormat(0, 5, "Details", "1", 1, "L", true, 0, "")

		for _, e := range events {
			pdf.CellFormat(35, 4, e.CreatedAt[:19], "1", 0, "L", false, 0, "")
			pdf.CellFormat(25, 4, e.EventType, "1", 0, "L", false, 0, "")

			details := e.Content
			if len(details) > 80 {
				details = details[:77] + "..."
			}
			pdf.CellFormat(0, 4, details, "1", 1, "L", false, 0, "")
		}
		pdf.Ln(4)
	}

	pdf.SetFont("Helvetica", "I", 7)
	pdf.SetTextColor(150, 150, 150)
	pdf.CellFormat(0, 5, "Generated by Trace v0.2.0", "", 1, "L", false, 0, "")

	var buf strings.Builder
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("pdf output: %w", err)
	}
	return []byte(buf.String()), nil
}

func (m *Manager) AddEvidence(ctx context.Context, caseID, fileName, filePath, mimeType, source string) error {
	stat, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("evidence file: %w", err)
	}
	id := uuid.New().String()
	_, err = m.db.ExecContext(ctx,
		`INSERT INTO case_evidence (id, case_id, file_name, file_path, mime_type, file_size, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, caseID, fileName, filePath, mimeType, stat.Size(), source, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (m *Manager) ListEvidence(ctx context.Context, caseID string) ([]Evidence, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, file_name, file_path, mime_type, file_size, source, created_at FROM case_evidence WHERE case_id = ? ORDER BY created_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var evs []Evidence
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.FileName, &e.FilePath, &e.MimeType, &e.FileSize, &e.Source, &e.CreatedAt); err != nil {
			return nil, err
		}
		evs = append(evs, e)
	}
	return evs, rows.Err()
}

func (m *Manager) LinkInvestigation(ctx context.Context, caseID, investigationID string) error {
	_, err := m.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO case_investigations (case_id, investigation_id, linked_at) VALUES (?, ?, ?)`,
		caseID, investigationID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("link investigation: %w", err)
	}
	_, err = m.db.ExecContext(ctx,
		`UPDATE cases SET updated_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), caseID)
	return err
}

func (m *Manager) ListLinkedInvestigations(ctx context.Context, caseID string) ([]string, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT investigation_id FROM case_investigations WHERE case_id = ? ORDER BY linked_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

type Evidence struct {
	ID        string `json:"id"`
	FileName  string `json:"file_name"`
	FilePath  string `json:"file_path"`
	MimeType  string `json:"mime_type"`
	FileSize  int64  `json:"file_size"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

func init() {
	_ = uuid.New
	_ = json.Marshal
}
