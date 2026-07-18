package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
)

type DashboardDataProvider interface {
	ListNodes(ctx context.Context) ([]NodeInfo, error)
	ListInvestigations(ctx context.Context, limit int, nodeID, statusFilter, search string) ([]ServerInvestigation, error)
	GetInvestigation(ctx context.Context, id string) (*ServerInvestigation, error)
	GetCorrelations(ctx context.Context, minCount int) ([]map[string]any, error)
}

type DashboardHandler struct {
	data DashboardDataProvider
}

func NewDashboardHandler(dp DashboardDataProvider) *DashboardHandler {
	return &DashboardHandler{data: dp}
}

func (dh *DashboardHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", dh.index)
	mux.HandleFunc("/investigations/", dh.detail)
	mux.HandleFunc("/search", dh.search)
	mux.HandleFunc("/correlations", dh.correlations)
}

func (dh *DashboardHandler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		dh.detail(w, r)
		return
	}

	ctx := r.Context()
	invs, err := dh.data.ListInvestigations(ctx, 50, "", "", "")
	if err != nil {
		invs = []ServerInvestigation{}
	}
	nodes, err := dh.data.ListNodes(ctx)
	if err != nil {
		nodes = []NodeInfo{}
	}
	corrs, err := dh.data.GetCorrelations(ctx, 2)
	if err != nil {
		corrs = []map[string]any{}
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>InnoIgniter Server</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { color: #58a6ff; font-size: 1.5em; margin-bottom: 8px; }
h2 { color: #58a6ff; font-size: 1.15em; margin: 24px 0 12px; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.stats { display: flex; gap: 16px; margin-bottom: 24px; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; flex: 1; }
.stat-value { font-size: 1.8em; font-weight: 700; color: #f0f6fc; }
.stat-label { font-size: 0.8em; color: #8b949e; margin-top: 4px; }
.search-box { display: flex; gap: 8px; margin-bottom: 16px; }
.search-box input { flex: 1; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 0.9em; }
.search-box button { padding: 8px 16px; background: #238636; color: #fff; border: none; border-radius: 6px; cursor: pointer; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.9em; }
th { color: #8b949e; font-weight: 600; }
tr:hover { background: #161b22; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.status-completed { color: #3fb950; }
.status-running, .status-active { color: #d29922; }
.status-failed { color: #f85149; }
.status-pending { color: #8b949e; }
.nav { display: flex; gap: 16px; margin-bottom: 16px; }
.nav a { color: #8b949e; font-size: 0.9em; }
.nav a.active { color: #58a6ff; font-weight: 600; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
.card-title { font-weight: 600; margin-bottom: 4px; }
.card-meta { font-size: 0.8em; color: #8b949e; }
.corr-high { color: #f85149; }
.corr-med { color: #d29922; }
.corr-low { color: #8b949e; }
@media (max-width: 768px) { .stats { flex-direction: column; } }
</style></head><body>
<div class="header"><h1>InnoIgniter Server</h1><div class="nav">
<a href="/" class="active">Dashboard</a><a href="/correlations">Correlations</a></div></div>

<div class="stats">
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", len(invs)) + `</div><div class="stat-label">Investigations</div></div>
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", len(nodes)) + `</div><div class="stat-label">Nodes</div></div>
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", len(corrs)) + `</div><div class="stat-label">Cross-node IOCs</div></div>
</div>

<form class="search-box" action="/search" method="get">
<input type="text" name="q" placeholder="Search by IOC, intent, or investigation ID...">
<button type="submit">Search</button>
</form>

<h2>Recent Investigations</h2>
<table><thead><tr><th>ID</th><th>Edge</th><th>Status</th><th>Intent</th><th>Confidence</th><th>Created</th></tr></thead><tbody>`)

	for _, inv := range invs {
		conf := "—"
		if inv.Confidence != nil {
			conf = fmt.Sprintf("%.0f%%", *inv.Confidence*100)
		}
		id := inv.ID
		if len(id) > 12 {
			id = id[:12]
		}
		edge := inv.SourceEdge
		if len(edge) > 12 {
			edge = edge[:12]
		}
		intent := inv.Intent
		if len(intent) > 60 {
			intent = intent[:57] + "..."
		}
		fmt.Fprintf(&b, `<tr><td><a href="/investigations/%s">%s</a></td><td>%s</td><td class="status-%s">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(inv.ID), html.EscapeString(id),
			html.EscapeString(edge), inv.Status, html.EscapeString(inv.Status),
			html.EscapeString(intent), conf, html.EscapeString(inv.CreatedAt))
	}

	b.WriteString(`</tbody></table></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (dh *DashboardHandler) detail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/investigations/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	inv, err := dh.data.GetInvestigation(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	conf := "—"
	if inv.Confidence != nil {
		conf = fmt.Sprintf("%.0f%%", *inv.Confidence*100)
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Investigation — ` + html.EscapeString(inv.ID[:12]) + `</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; max-width: 960px; margin: 0 auto; }
h1 { color: #58a6ff; font-size: 1.5em; }
a { color: #58a6ff; }
.field { margin: 8px 0; }
.label { color: #8b949e; display: inline-block; width: 120px; font-size: 0.85em; }
.report { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-top: 16px; white-space: pre-wrap; font-family: monospace; font-size: 0.85em; line-height: 1.5; }
.status-completed { color: #3fb950; }
.status-running { color: #d29922; }
.status-failed { color: #f85149; }
</style></head><body>
<h1>Investigation ` + html.EscapeString(inv.ID[:12]) + `</h1>
<div class="field"><span class="label">ID:</span>` + html.EscapeString(inv.ID) + `</div>
<div class="field"><span class="label">Edge:</span>` + html.EscapeString(inv.SourceEdge) + `</div>
<div class="field"><span class="label">Status:</span><span class="status-` + inv.Status + `">` + html.EscapeString(inv.Status) + `</span></div>
<div class="field"><span class="label">Intent:</span>` + html.EscapeString(inv.Intent) + `</div>
<div class="field"><span class="label">Playbook:</span>` + html.EscapeString(inv.Playbook) + `</div>
<div class="field"><span class="label">Confidence:</span>` + conf + `</div>
<div class="field"><span class="label">Created:</span>` + html.EscapeString(inv.CreatedAt) + `</div>
<div class="field"><span class="label">Updated:</span>` + html.EscapeString(inv.UpdatedAt) + `</div>`)

	if len(inv.Indicators) > 0 {
		b.WriteString(`<h2>Indicators</h2><ul>`)
		for _, ind := range inv.Indicators {
			b.WriteString(`<li><code>` + html.EscapeString(ind) + `</code></li>`)
		}
		b.WriteString(`</ul>`)
	}

	if inv.Report != "" {
		b.WriteString(`<div class="report">` + html.EscapeString(inv.Report) + `</div>`)
	}

	b.WriteString(`<p style="margin-top:16px"><a href="/">← Back</a></p>`)
	b.WriteString(`</body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (dh *DashboardHandler) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	ctx := r.Context()

	invs, err := dh.data.ListInvestigations(ctx, 100, "", "", q)
	if err != nil {
		invs = []ServerInvestigation{}
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Search — InnoIgniter Server</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { color: #58a6ff; font-size: 1.5em; }
a { color: #58a6ff; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.9em; }
th { color: #8b949e; }
tr:hover { background: #161b22; }
.status-completed { color: #3fb950; }
.status-failed { color: #f85149; }
</style></head><body>
<h1>Search: ` + html.EscapeString(q) + `</h1>
<p>` + fmt.Sprintf("%d results", len(invs)) + `</p>`)

	if len(invs) > 0 {
		b.WriteString(`<table><thead><tr><th>ID</th><th>Status</th><th>Intent</th><th>Created</th></tr></thead><tbody>`)
		for _, inv := range invs {
			id := inv.ID
			if len(id) > 12 {
				id = id[:12]
			}
			intent := inv.Intent
			if len(intent) > 60 {
				intent = intent[:57] + "..."
			}
			fmt.Fprintf(&b, `<tr><td><a href="/investigations/%s">%s</a></td><td class="status-%s">%s</td><td>%s</td><td>%s</td></tr>`,
				html.EscapeString(inv.ID), html.EscapeString(id),
				inv.Status, html.EscapeString(inv.Status),
				html.EscapeString(intent), html.EscapeString(inv.CreatedAt))
		}
		b.WriteString(`</tbody></table>`)
	}

	b.WriteString(`<p><a href="/">← Back</a></p></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (dh *DashboardHandler) correlations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	corrs, err := dh.data.GetCorrelations(ctx, 2)
	if err != nil {
		corrs = []map[string]any{}
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Correlations — InnoIgniter Server</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { color: #58a6ff; font-size: 1.5em; }
a { color: #58a6ff; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.9em; }
th { color: #8b949e; }
tr:hover { background: #161b22; }
.corr-high { color: #f85149; font-weight: 600; }
.corr-med { color: #d29922; }
.nav { display: flex; gap: 16px; margin-bottom: 16px; }
.nav a { color: #8b949e; font-size: 0.9em; }
.nav a.active { color: #58a6ff; font-weight: 600; }
</style></head><body>
<div class="nav"><a href="/">Dashboard</a><a href="/correlations" class="active">Correlations</a></div>
<h1>Cross-Node IOC Correlations</h1>
<p style="color:#8b949e;margin-bottom:16px">IOCs seen on 2+ nodes indicate broader campaigns.</p>`)

	if len(corrs) > 0 {
		b.WriteString(`<table><thead><tr><th>IOC</th><th>Nodes</th><th>Confidence</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>`)
		for _, c := range corrs {
			ioc, _ := c["ioc"].(string)
			count, _ := c["node_count"].(float64)
			conf, _ := c["confidence"].(float64)
			first, _ := c["first_seen"].(string)
			last, _ := c["last_seen"].(string)

			cls := "corr-low"
			if conf >= 0.8 {
				cls = "corr-high"
			} else if conf >= 0.6 {
				cls = "corr-med"
			}

			iocShort := ioc
			if len(iocShort) > 24 {
				iocShort = iocShort[:21] + "..."
			}

			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%.0f</td><td class="%s">%.0f%%</td><td>%s</td><td>%s</td></tr>`,
				html.EscapeString(iocShort), count, cls, conf*100, html.EscapeString(first), html.EscapeString(last))
		}
		b.WriteString(`</tbody></table>`)
	} else {
		b.WriteString(`<p style="color:#8b949e;margin-top:16px">No cross-node correlations yet. Run investigations on multiple edge nodes to see correlations.</p>`)
	}

	b.WriteString(`</body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func init() {
	_ = json.Marshal
}
