package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/yanmyoaung2004/trace/internal/locale"
)

type DashboardDataProvider interface {
	ListNodes(ctx context.Context) ([]NodeInfo, error)
	ListInvestigations(ctx context.Context, limit int, nodeID, statusFilter, search string) ([]ServerInvestigation, error)
	GetInvestigation(ctx context.Context, id string) (*ServerInvestigation, error)
	GetCorrelations(ctx context.Context, minCount int) ([]map[string]any, error)
}

type DashboardHandler struct {
	data DashboardDataProvider
	db   *sql.DB
}

func NewDashboardHandler(dp DashboardDataProvider) *DashboardHandler {
	return &DashboardHandler{data: dp}
}

func (dh *DashboardHandler) WithDB(database *sql.DB) *DashboardHandler {
	dh.db = database
	return dh
}

func (dh *DashboardHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", dh.index)
	mux.HandleFunc("/investigations/", dh.detail)
	mux.HandleFunc("/correlations", dh.correlations)
	mux.HandleFunc("/cases", dh.cases)
	mux.HandleFunc("/api/live", dh.liveData)
}

const pageStyle = `
:root {
  --bg:      oklch(0.07 0 0);
  --surface: oklch(0.11 0.008 60);
  --surface-hover: oklch(0.15 0.008 60);
  --border:  oklch(0.18 0.008 60);
  --ink:     oklch(0.93 0.008 60);
  --muted:   oklch(0.50 0.02 60);
  --primary: oklch(0.55 0.124 60);
  --primary-dim: oklch(0.45 0.10 60);
  --accent:  oklch(0.55 0.12 220);
  --success: oklch(0.60 0.15 150);
  --warning: oklch(0.65 0.14 80);
  --danger:  oklch(0.55 0.18 30);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, system-ui, sans-serif; background: var(--bg); color: var(--ink); padding: 24px; font-size: 14px; line-height: 1.5; -webkit-font-smoothing: antialiased; }
h1 { color: var(--ink); font-size: 1.25rem; font-weight: 700; letter-spacing: -0.01em; }
h2 { color: var(--ink); font-size: 0.9375rem; font-weight: 600; margin: 24px 0 12px; letter-spacing: -0.005em; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
table { width: 100%; border-collapse: separate; border-spacing: 0; }
th { padding: 10px 14px; text-align: left; font-size: 0.75rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; border-bottom: 1px solid var(--border); white-space: nowrap; }
td { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 0.875rem; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--surface-hover); }
code { background: var(--surface); padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }
.badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 100px; font-size: 0.75rem; font-weight: 600; line-height: 1; }
.badge-completed { background: oklch(0.60 0.15 150 / 0.15); color: var(--success); }
.badge-running { background: oklch(0.65 0.14 80 / 0.15); color: var(--warning); }
.badge-failed { background: oklch(0.55 0.18 30 / 0.15); color: var(--danger); }
.badge-pending { background: oklch(0.50 0.02 60 / 0.15); color: var(--muted); }
.badge::before { content: ''; display: inline-block; width: 5px; height: 5px; border-radius: 50%; }
.badge-completed::before { background: var(--success); }
.badge-running::before { background: var(--warning); }
.badge-failed::before { background: var(--danger); }
.badge-pending::before { background: var(--muted); }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
.header-right { display: flex; gap: 16px; align-items: center; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 24px; }
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px; position: relative; overflow: hidden; }
.stat::after { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
.stat:nth-child(1)::after { background: var(--accent); }
.stat:nth-child(2)::after { background: var(--primary); }
.stat:nth-child(3)::after { background: var(--success); }
.stat:nth-child(4)::after { background: var(--warning); }
.stat-value { font-size: 1.75rem; font-weight: 700; color: var(--ink); letter-spacing: -0.02em; line-height: 1.2; }
.stat-label { font-size: 0.6875rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
.stat-bar { height: 3px; border-radius: 2px; margin-top: 10px; background: var(--border); overflow: hidden; }
.stat-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
.filters { display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }
.filter-btn { display: inline-flex; align-items: center; padding: 6px 14px; border: 1px solid var(--border); border-radius: 100px; background: transparent; color: var(--muted); cursor: pointer; font-size: 0.8125rem; font-weight: 500; transition: all 0.15s ease; line-height: 1; }
.filter-btn:hover { border-color: var(--accent); color: var(--accent); }
.filter-btn.active { background: oklch(0.55 0.12 220 / 0.12); border-color: var(--accent); color: var(--accent); }
.search-box { display: flex; gap: 0; margin-bottom: 16px; }
.search-box input { flex: 1; padding: 9px 14px; background: var(--surface); border: 1px solid var(--border); border-right: none; border-radius: 8px 0 0 8px; color: var(--ink); font-size: 0.875rem; outline: none; transition: border-color 0.15s; }
.search-box input:focus { border-color: var(--accent); }
.search-box input::placeholder { color: var(--muted); opacity: 0.7; }
.search-box button { padding: 9px 16px; background: var(--primary); color: oklch(0.93 0.008 60); border: none; border-radius: 0 8px 8px 0; cursor: pointer; font-weight: 600; font-size: 0.8125rem; transition: background 0.15s; }
.search-box button:hover { background: var(--primary-dim); }
.conf-bar { display: inline-flex; align-items: center; gap: 6px; }
.conf-bar-track { width: 64px; height: 5px; border-radius: 3px; background: var(--border); overflow: hidden; display: inline-block; vertical-align: middle; }
.conf-bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s ease; }
.conf-high .conf-bar-fill { background: var(--danger); }
.conf-med .conf-bar-fill { background: var(--warning); }
.conf-low .conf-bar-fill { background: var(--success); }
.auto-refresh { font-size: 0.75rem; color: var(--muted); display: inline-flex; align-items: center; gap: 6px; }
.auto-refresh .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--success); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
.nav { display: flex; gap: 4px; }
.nav a { padding: 6px 12px; border-radius: 6px; font-size: 0.8125rem; font-weight: 500; color: var(--muted); transition: all 0.15s; }
.nav a:hover { color: var(--ink); background: var(--surface-hover); text-decoration: none; }
.nav a.active { background: oklch(0.55 0.12 220 / 0.1); color: var(--accent); }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-top: 16px; }
.field { display: flex; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
.field:last-child { border-bottom: none; }
.label { color: var(--muted); min-width: 120px; font-size: 0.8125rem; }
.report { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-top: 12px; white-space: pre-wrap; font-family: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', Consolas, monospace; font-size: 0.8125rem; line-height: 1.6; color: var(--ink); }
.tag { display: inline-flex; align-items: center; background: oklch(0.55 0.12 220 / 0.08); color: var(--accent); padding: 4px 10px; border-radius: 6px; font-size: 0.8125rem; margin: 2px; font-family: 'SF Mono', 'Cascadia Code', monospace; }
.tag code { background: none; padding: 0; }
.timeline-event { display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 0.8125rem; align-items: flex-start; }
.timeline-event:last-child { border-bottom: none; }
.tl-time { color: var(--muted); min-width: 155px; font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 0.8125rem; }
.tl-type { color: var(--accent); min-width: 120px; font-weight: 600; font-size: 0.8125rem; }
.tl-summary { color: var(--ink); font-size: 0.8125rem; }
.empty-state { text-align: center; padding: 48px 24px; color: var(--muted); }
.empty-state p { font-size: 0.875rem; margin-top: 8px; }
@media (max-width: 768px) { .stats { grid-template-columns: repeat(2, 1fr); } body { padding: 12px; } .tl-time { min-width: 100px; } }
`

func (dh *DashboardHandler) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		dh.detail(w, r)
		return
	}

	ctx := r.Context()
	statusFilter := r.URL.Query().Get("status")
	search := r.URL.Query().Get("q")

	invs, err := dh.data.ListInvestigations(ctx, 50, "", statusFilter, search)
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

	var complCount, failCount, runCount, pendCount int
	for _, inv := range invs {
		switch inv.Status {
		case "completed":
			complCount++
		case "failed":
			failCount++
		case "running":
			runCount++
		default:
			pendCount++
		}
	}
	total := len(invs)
	complPct := 0.0
	if total > 0 {
		complPct = float64(complCount) / float64(total) * 100
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>` + locale.T("dashboard_title") + `</title>
<style>` + pageStyle + `</style></head><body>
<div class="header">
<h1>` + locale.T("dashboard_title") + `</h1>
<div class="header-right">
<span class="auto-refresh"><span class="dot"></span>` + locale.T("dashboard_auto_refresh") + `</span>
<div class="nav"><a href="/" class="active">` + locale.T("dashboard_investigations") + `</a><a href="/correlations">` + locale.T("dashboard_correlations") + `</a></div>
</div></div>

<div class="stats">
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", total) + `</div><div class="stat-label">` + locale.T("dashboard_investigations") + `</div>` +
		confBar(complPct, complCount) + `</div>
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", len(nodes)) + `</div><div class="stat-label">` + locale.T("dashboard_nodes") + `</div></div>
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", len(corrs)) + `</div><div class="stat-label">Cross-node IOCs</div></div>
<div class="stat"><div class="stat-value" style="color:` + statusColor(complCount, failCount, runCount) + `">` + fmt.Sprintf("%d", complCount) + ` ✓ / ` + fmt.Sprintf("%d", failCount) + ` ✗</div><div class="stat-label">` + locale.T("dashboard_completed") + ` / ` + locale.T("dashboard_failed") + `</div></div>
</div>

<form class="search-box" action="/" method="get">
<input type="text" name="q" placeholder="` + locale.T("dashboard_search_placeholder") + `" value="` + html.EscapeString(search) + `">
<button type="submit">` + locale.T("dashboard_search") + `</button>
</form>

<div class="filters" id="filterBar">
<a href="/" class="filter-btn` + filterClass("", statusFilter) + `">` + locale.T("dashboard_all") + `</a>
<a href="/?status=completed" class="filter-btn` + filterClass("completed", statusFilter) + `">` + locale.T("dashboard_completed") + `</a>
<a href="/?status=running" class="filter-btn` + filterClass("running", statusFilter) + `">` + locale.T("dashboard_running") + `</a>
<a href="/?status=failed" class="filter-btn` + filterClass("failed", statusFilter) + `">` + locale.T("dashboard_failed") + `</a>
<a href="/?status=pending" class="filter-btn` + filterClass("pending", statusFilter) + `">` + locale.T("dashboard_pending") + `</a>
</div>

<table class="card" style="padding:0;margin-top:0"><thead><tr><th>` + locale.T("dashboard_id") + `</th><th>` + locale.T("dashboard_edge") + `</th><th>` + locale.T("dashboard_status") + `</th><th>` + locale.T("dashboard_intent") + `</th><th>` + locale.T("dashboard_confidence") + `</th><th>` + locale.T("dashboard_created") + `</th></tr></thead><tbody>`)

	if len(invs) == 0 {
		b.WriteString(`<tr><td colspan="6"><div class="empty-state"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.4"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/><path d="M11 8v6"/><path d="M8 11h6"/></svg><p>` + locale.T("dashboard_no_results") + `</p></div></td></tr>`)
	} else {
		for _, inv := range invs {
			conf := "—"
			if inv.Confidence != nil {
				conf = confBarVisual(*inv.Confidence)
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
			fmt.Fprintf(&b, `<tr><td><a href="/investigations/%s">%s</a></td><td>%s</td><td><span class="badge badge-%s">%s</span></td><td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">%s</td><td>%s</td><td style="white-space:nowrap;color:var(--muted);font-size:0.8125rem">%s</td></tr>`,
				html.EscapeString(inv.ID), html.EscapeString(id),
				html.EscapeString(edge),
				inv.Status, html.EscapeString(inv.Status),
				html.EscapeString(intent), conf,
				html.EscapeString(inv.CreatedAt))
		}
	}

	b.WriteString(`</tbody></table>
<script>
setTimeout(function(){ location.reload(); }, 15000);
var filterBtns = document.querySelectorAll('.filter-btn');
filterBtns.forEach(function(btn) {
  btn.addEventListener('click', function(e) {
    filterBtns.forEach(function(b) { b.classList.remove('active'); });
    this.classList.add('active');
  });
});
</script>
</body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (dh *DashboardHandler) liveData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	ctx := r.Context()
	invs, err := dh.data.ListInvestigations(ctx, 10, "", "", "")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}

	var out []map[string]any
	for _, inv := range invs {
		id := inv.ID
		if len(id) > 12 {
			id = id[:12]
		}
		out = append(out, map[string]any{
			"id":         id,
			"status":     inv.Status,
			"intent":     inv.Intent,
			"confidence": inv.Confidence,
			"created_at": inv.CreatedAt,
		})
	}
	json.NewEncoder(w).Encode(map[string]any{
		"investigations": out,
		"time":           time.Now().UTC().Format(time.RFC3339),
	})
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
<title>` + locale.T("dashboard_detail") + ` — ` + html.EscapeString(inv.ID[:12]) + `</title>
<style>` + pageStyle + `
body { max-width: 960px; margin: 0 auto; }
</style></head><body>
<div class="header"><h1>` + locale.T("dashboard_detail") + ` ` + html.EscapeString(inv.ID[:12]) + `</h1>
<a href="/">` + locale.T("dashboard_back") + `</a></div>

<div class="card">
<div class="field"><span class="label">` + locale.T("dashboard_id") + `</span>` + html.EscapeString(inv.ID) + `</div>
<div class="field"><span class="label">` + locale.T("dashboard_edge") + `</span>` + html.EscapeString(inv.SourceEdge) + `</div>
<div class="field"><span class="label">` + locale.T("dashboard_status") + `</span><span class="badge badge-` + inv.Status + `">` + html.EscapeString(inv.Status) + `</span></div>
<div class="field"><span class="label">` + locale.T("dashboard_intent") + `</span>` + html.EscapeString(inv.Intent) + `</div>
<div class="field"><span class="label">` + locale.T("dashboard_playbook") + `</span>` + html.EscapeString(inv.Playbook) + `</div>
<div class="field"><span class="label">` + locale.T("dashboard_confidence") + `</span>` + conf + `</div>
<div class="field"><span class="label">` + locale.T("dashboard_created") + `</span>` + html.EscapeString(inv.CreatedAt) + `</div>
<div class="field"><span class="label">` + locale.T("dashboard_updated") + `</span>` + html.EscapeString(inv.UpdatedAt) + `</div>
</div>`)

	if len(inv.Indicators) > 0 {
		b.WriteString(`<div class="card"><h2>` + locale.T("dashboard_indicators") + `</h2>`)
		for _, ind := range inv.Indicators {
			b.WriteString(`<span class="tag"><code>` + html.EscapeString(ind) + `</code></span> `)
		}
		b.WriteString(`</div>`)
	}

	if inv.Report != "" {
		b.WriteString(`<div class="card"><h2>` + locale.T("dashboard_full_report") + `</h2><div class="report">` + html.EscapeString(inv.Report) + `</div></div>`)
	}

	b.WriteString(`<div class="card"><h2>` + locale.T("dashboard_timeline") + `</h2>
<div id="timeline"><p style="color:#8b949e;">` + locale.T("dashboard_timeline_loading") + `</p></div>
</div>

<script>
var _tlEmpty = ` + jsStr(locale.T("dashboard_timeline_empty")) + `;
var _tlFailed = ` + jsStr(locale.T("dashboard_timeline_failed")) + `;
fetch('/api/v1/timeline/` + inv.ID + `')
  .then(r => r.json())
  .then(events => {
    var html = '';
    if (events.length === 0) { html = '<p style="color:#8b949e;">' + _tlEmpty + '</p>'; }
    else {
      events.forEach(function(e) {
        var ts = e.ts ? e.ts.substring(0, 19).replace('T', ' ') : '--';
        var type = e.type || 'unknown';
        var summary = '';
        if (e.data) {
          if (e.data.agent) summary += ' agent=' + e.data.agent;
          if (e.data.action) summary += ' action=' + e.data.action;
          if (e.data.playbook) summary += ' playbook=' + e.data.playbook;
          if (e.data.step !== undefined) summary += ' step=' + e.data.step;
          if (e.data.error) summary += ' error=' + JSON.stringify(e.data.error);
        }
        html += '<div class="timeline-event"><span class="tl-time">' + ts + '</span><span class="tl-type">' + type + '</span><span class="tl-summary">' + summary + '</span></div>';
      });
    }
    document.getElementById('timeline').innerHTML = html;
  })
  .catch(function() { document.getElementById('timeline').innerHTML = '<p style="color:#f85149;">' + _tlFailed + '</p>'; });
</script>` + "\n")

	b.WriteString(`</body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (dh *DashboardHandler) search(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/?"+r.URL.RawQuery, http.StatusFound)
}

func (dh *DashboardHandler) correlations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	corrs, err := dh.data.GetCorrelations(ctx, 1)
	if err != nil {
		corrs = []map[string]any{}
	}

	highCount, medCount, lowCount := 0, 0, 0
	for _, c := range corrs {
		conf, _ := c["confidence"].(float64)
		if conf >= 0.8 {
			highCount++
		} else if conf >= 0.6 {
			medCount++
		} else {
			lowCount++
		}
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Correlations — Trace Server</title>
<style>` + pageStyle + `</style></head><body>
<div class="header"><h1>Cross-Node IOC Correlations</h1>
<div class="nav"><a href="/">Dashboard</a><a href="/correlations" class="active">Correlations</a></div></div>

<div class="stats">
<div class="stat"><div class="stat-value" style="color:var(--danger)">` + fmt.Sprintf("%d", highCount) + `</div><div class="stat-label">High Confidence (3+ nodes)</div></div>
<div class="stat"><div class="stat-value" style="color:var(--warning)">` + fmt.Sprintf("%d", medCount) + `</div><div class="stat-label">Medium (2 nodes)</div></div>
<div class="stat"><div class="stat-value" style="color:var(--success)">` + fmt.Sprintf("%d", lowCount) + `</div><div class="stat-label">Low (1 node)</div></div>
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", len(corrs)) + `</div><div class="stat-label">Total IOCs</div></div>
</div>

<p style="color:var(--muted);margin-bottom:16px;font-size:0.875rem">IOCs seen on 3+ nodes indicate broader campaigns with high confidence.</p>`)

	if len(corrs) > 0 {
		b.WriteString(`<table><thead><tr><th>IOC</th><th>Nodes</th><th>Confidence</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>`)
		for _, c := range corrs {
			ioc, _ := c["ioc"].(string)
			count, _ := c["node_count"].(float64)
			conf, _ := c["confidence"].(float64)

			clr := "var(--muted)"
			if conf >= 0.8 {
				clr = "var(--danger)"
			} else if conf >= 0.6 {
				clr = "var(--warning)"
			}

			first, _ := c["first_seen"].(string)
			last, _ := c["last_seen"].(string)

			iocShort := ioc
			if len(iocShort) > 24 {
				iocShort = iocShort[:21] + "..."
			}

			fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%.0f</td><td style="color:%s">%.0f%% <div class="conf-bar"><div class="conf-fill" style="width:%.0f%%;background:%s"></div></div></td><td>%s</td><td>%s</td></tr>`,
				html.EscapeString(iocShort), count, clr, conf*100, conf*100, clr, html.EscapeString(first), html.EscapeString(last))
		}
		b.WriteString(`</tbody></table>`)
	} else {
		b.WriteString(`<p style="color:#8b949e;margin-top:24px;text-align:center">No correlations yet. Run investigations on multiple edge nodes to see cross-node IOC data.</p>`)
	}

	b.WriteString(`</body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (dh *DashboardHandler) cases(w http.ResponseWriter, r *http.Request) {
	if dh.db == nil {
		http.Error(w, "cases not available (no database)", http.StatusNotFound)
		return
	}

	rows, err := dh.db.Query(`SELECT id, title, description, status, severity, assignee, created_at FROM cases ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Cases — Trace Server</title>
<style>` + pageStyle + `</style></head><body>
<div class="header"><h1>Security Cases</h1>
<div class="nav"><a href="/">` + locale.T("dashboard_investigations") + `</a><a href="/correlations">` + locale.T("dashboard_correlations") + `</a><a href="/cases" class="active">Cases</a></div></div>

<table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Assignee</th><th>Created</th></tr></thead><tbody>`)

	hasRows := false
	for rows.Next() {
		hasRows = true
		var id, title, desc, status, severity, assignee, created string
		rows.Scan(&id, &title, &desc, &status, &severity, &assignee, &created)

		as := assignee
		if as == "" { as = "—" }

		idShort := id
		if len(idShort) > 12 { idShort = idShort[:12] }

		fmt.Fprintf(&b, `<tr><td><a href="/cases/%s">%s</a></td><td>%s</td><td><span class="badge badge-%s">%s</span></td><td><span class="badge badge-%s">%s</span></td><td>%s</td><td style="white-space:nowrap;color:var(--muted)">%s</td></tr>`,
			html.EscapeString(id), html.EscapeString(idShort),
			html.EscapeString(title),
			status, html.EscapeString(status),
			severity, html.EscapeString(severity),
			html.EscapeString(as),
			created[:19])
	}

	if !hasRows {
		b.WriteString(`<tr><td colspan="6"><div class="empty-state"><p>No cases yet. Cases are auto-created when SIEM alerts fire with severity ≥ 4.</p></div></td></tr>`)
	}

	b.WriteString(`</tbody></table></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func confBar(pct float64, count int) string {
	return fmt.Sprintf(`<div class="stat-bar"><div class="stat-bar-fill" style="width:%.0f%%;background:var(--accent)"></div></div>`, pct)
}

func jsStr(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func confBarVisual(conf float64) string {
	cls := "conf-low"
	pct := conf * 100
	if conf >= 0.7 {
		cls = "conf-high"
	} else if conf >= 0.4 {
		cls = "conf-med"
	}
	return fmt.Sprintf(`<span class="conf-bar %s"><span class="conf-bar-track"><span class="conf-bar-fill" style="width:%.0f%%"></span></span><span style="font-size:0.75rem;color:var(--muted)">%.0f%%</span></span>`, cls, pct, pct)
}

func filterClass(status, current string) string {
	if status == current || (status == "" && current == "") {
		return " active"
	}
	return ""
}

func statusColor(compl, fail, run int) string {
	if fail > 0 {
		return "var(--danger)"
	}
	if run > 0 {
		return "var(--warning)"
	}
	return "var(--success)"
}

func init() {
	_ = time.Now
	_ = json.Marshal
}
