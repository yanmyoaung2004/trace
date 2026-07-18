package exporter

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/innoigniter/edge/internal/agent"
)

type Agent struct {
	db *sql.DB
	srv *http.Server
}

func New(database *sql.DB) *Agent {
	return &Agent{db: database}
}

func (a *Agent) Name() string { return "exporter" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "serve_reports", Inputs: []string{"addr"}, Outputs: []string{"status"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "serve_reports":
		return a.serveReports(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) serveReports(_ context.Context, input agent.Input) (agent.Output, error) {
	addr, _ := input["addr"].(string)
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.listHandler)
	mux.HandleFunc("/investigation/", a.detailHandler)

	a.srv = &http.Server{Addr: addr, Handler: mux}
	go func() {
		a.srv.ListenAndServe()
	}()

	return agent.Output{
		"status": "started",
		"addr":   addr,
	}, nil
}

func (a *Agent) Stop() {
	if a.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a.srv.Shutdown(ctx)
	}
}

func (a *Agent) listHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	rows, err := a.db.Query(`SELECT id, status, intent, created_at FROM investigations ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>InnoIgniterAI — Investigations</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; }
th { color: #8b949e; font-weight: 600; }
tr:hover { background: #161b22; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.status-completed { color: #3fb950; }
.status-running { color: #d29922; }
.status-failed { color: #f85149; }
.status-pending { color: #8b949e; }
</style></head><body>
<h1>Investigation Reports</h1>
<table><thead><tr><th>ID</th><th>Status</th><th>Intent</th><th>Created</th></tr></thead><tbody>`)

	for rows.Next() {
		var id, status, intent, createdAt string
		rows.Scan(&id, &status, &intent, &createdAt)
		fmt.Fprintf(&b, `<tr><td><a href="/investigation/%s">%s</a></td><td class="status-%s">%s</td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(id), html.EscapeString(id[:12]), status, html.EscapeString(status), html.EscapeString(intent), html.EscapeString(createdAt))
	}

	b.WriteString(`</tbody></table></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (a *Agent) detailHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/investigation/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	var status, intent, createdAt, updatedAt string
	var confidence *float64
	err := a.db.QueryRow(
		`SELECT status, intent, created_at, updated_at, confidence FROM investigations WHERE id = ?`, id,
	).Scan(&status, &intent, &createdAt, &updatedAt, &confidence)

	if err != nil {
		http.NotFound(w, r)
		return
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Investigation — ` + html.EscapeString(id[:12]) + `</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; }
.field { margin: 8px 0; }
.label { color: #8b949e; font-size: 0.85em; display: inline-block; width: 120px; }
.value { color: #c9d1d9; }
a { color: #58a6ff; }
</style></head><body>
<h1>Investigation Report</h1>
<div class="field"><span class="label">ID:</span><span class="value">` + html.EscapeString(id) + `</span></div>
<div class="field"><span class="label">Status:</span><span class="value status-` + status + `">` + html.EscapeString(status) + `</span></div>
<div class="field"><span class="label">Intent:</span><span class="value">` + html.EscapeString(intent) + `</span></div>
<div class="field"><span class="label">Created:</span><span class="value">` + html.EscapeString(createdAt) + `</span></div>
<div class="field"><span class="label">Updated:</span><span class="value">` + html.EscapeString(updatedAt) + `</span></div>`)

	if confidence != nil {
		fmt.Fprintf(&b, `<div class="field"><span class="label">Confidence:</span><span class="value">%.0f%%</span></div>`, *confidence*100)
	}

	rows, err := a.db.Query(`SELECT id, agent, action, status, created_at FROM tasks WHERE investigation_id = ? ORDER BY created_at`, id)
	if err == nil {
		defer rows.Close()
		b.WriteString(`<h2>Tasks</h2><table><thead><tr><th>ID</th><th>Agent</th><th>Action</th><th>Status</th><th>Created</th></tr></thead><tbody>`)
		for rows.Next() {
			var taskID, agent, action, taskStatus, taskCreated string
			rows.Scan(&taskID, &agent, &action, &taskStatus, &taskCreated)
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td>%s</td><td class="status-%s">%s</td><td>%s</td></tr>`,
				html.EscapeString(taskID[:8]), html.EscapeString(agent), html.EscapeString(action), taskStatus, html.EscapeString(taskStatus), html.EscapeString(taskCreated))
		}
		b.WriteString(`</tbody></table>`)
	}

	b.WriteString(`<p><a href="/">← Back to list</a></p>`)
	b.WriteString(`</body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}
