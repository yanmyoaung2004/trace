package server

import (
	"context"
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
}

func NewDashboardHandler(dp DashboardDataProvider) *DashboardHandler {
	return &DashboardHandler{data: dp}
}

func (dh *DashboardHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", dh.index)
	mux.HandleFunc("/investigations/", dh.detail)
	mux.HandleFunc("/search", dh.search)
	mux.HandleFunc("/correlations", dh.correlations)
	mux.HandleFunc("/api/live", dh.liveData)
}

const pageStyle = `
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
h1 { color: #58a6ff; font-size: 1.5em; }
h2 { color: #58a6ff; font-size: 1.15em; margin: 20px 0 12px; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.9em; }
th { color: #8b949e; font-weight: 600; }
tr:hover { background: #161b22; }
code { background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
.status-completed, .badge-completed { color: #3fb950; }
.status-running, .status-active, .badge-running { color: #d29922; }
.status-failed, .badge-failed { color: #f85149; }
.status-pending, .badge-pending { color: #8b949e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
.badge-completed { background: rgba(63,185,80,0.15); color: #3fb950; }
.badge-running { background: rgba(210,153,34,0.15); color: #d29922; }
.badge-failed { background: rgba(248,81,73,0.15); color: #f85149; }
.badge-pending { background: rgba(139,148,158,0.15); color: #8b949e; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px; }
.header-right { display: flex; gap: 12px; align-items: center; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
.stat-value { font-size: 1.6em; font-weight: 700; color: #f0f6fc; }
.stat-label { font-size: 0.75em; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-bar { height: 4px; border-radius: 2px; margin-top: 8px; background: #30363d; overflow: hidden; }
.stat-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s; }
.filters { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
.filter-btn { padding: 6px 14px; border: 1px solid #30363d; border-radius: 20px; background: transparent; color: #8b949e; cursor: pointer; font-size: 0.85em; transition: all 0.15s; }
.filter-btn:hover { border-color: #58a6ff; color: #58a6ff; }
.filter-btn.active { background: rgba(88,166,255,0.15); border-color: #58a6ff; color: #58a6ff; }
.search-box { display: flex; gap: 8px; margin-bottom: 16px; }
.search-box input { flex: 1; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 0.9em; outline: none; }
.search-box input:focus { border-color: #58a6ff; }
.search-box button { padding: 8px 16px; background: #238636; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
.search-box button:hover { background: #2ea043; }
.conf-bar { display: inline-block; width: 60px; height: 6px; border-radius: 3px; background: #30363d; vertical-align: middle; margin-right: 6px; overflow: hidden; }
.conf-fill { height: 100%; border-radius: 3px; }
.conf-high .conf-fill { background: #f85149; width: 100%; }
.conf-med .conf-fill { background: #d29922; width: 66%; }
.conf-low .conf-fill { background: #3fb950; width: 33%; }
.auto-refresh { font-size: 0.8em; color: #8b949e; }
.auto-refresh .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #3fb950; margin-right: 4px; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
.nav { display: flex; gap: 16px; }
.nav a { color: #8b949e; font-size: 0.9em; padding-bottom: 2px; border-bottom: 2px solid transparent; }
.nav a:hover { color: #c9d1d9; }
.nav a.active { color: #58a6ff; border-bottom-color: #58a6ff; }
.timeline-event { display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid #21262d; font-size: 0.85em; align-items: flex-start; }
.timeline-event:last-child { border-bottom: none; }
.tl-time { color: #8b949e; min-width: 160px; font-family: monospace; font-size: 0.9em; }
.tl-type { color: #58a6ff; min-width: 120px; font-weight: 600; }
.tl-summary { color: #c9d1d9; }
@media (max-width: 768px) { .stats { grid-template-columns: repeat(2, 1fr); } body { padding: 12px; } }
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

<h2>` + locale.T("dashboard_investigations") + `</h2>
<table><thead><tr><th>` + locale.T("dashboard_id") + `</th><th>` + locale.T("dashboard_edge") + `</th><th>` + locale.T("dashboard_status") + `</th><th>` + locale.T("dashboard_intent") + `</th><th>` + locale.T("dashboard_confidence") + `</th><th>` + locale.T("dashboard_created") + `</th></tr></thead><tbody>`)

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
		fmt.Fprintf(&b, `<tr><td><a href="/investigations/%s">%s</a></td><td>%s</td><td><span class="badge badge-%s">%s</span></td><td>%s</td><td>%s</td><td style="white-space:nowrap">%s</td></tr>`,
			html.EscapeString(inv.ID), html.EscapeString(id),
			html.EscapeString(edge),
			inv.Status, html.EscapeString(inv.Status),
			html.EscapeString(intent), conf,
			html.EscapeString(inv.CreatedAt))
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
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-top: 20px; }
.field { display: flex; padding: 6px 0; border-bottom: 1px solid #161b22; }
.field:last-child { border-bottom: none; }
.label { color: #8b949e; min-width: 120px; font-size: 0.85em; }
.report { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-top: 16px; white-space: pre-wrap; font-family: monospace; font-size: 0.85em; line-height: 1.6; }
.tag { display: inline-block; background: rgba(88,166,255,0.1); color: #58a6ff; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin: 2px; }
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
<div class="stat"><div class="stat-value" style="color:#f85149">` + fmt.Sprintf("%d", highCount) + `</div><div class="stat-label">High Confidence (3+ nodes)</div></div>
<div class="stat"><div class="stat-value" style="color:#d29922">` + fmt.Sprintf("%d", medCount) + `</div><div class="stat-label">Medium (2 nodes)</div></div>
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", lowCount) + `</div><div class="stat-label">Low (1 node)</div></div>
<div class="stat"><div class="stat-value">` + fmt.Sprintf("%d", len(corrs)) + `</div><div class="stat-label">Total IOCs</div></div>
</div>

<p style="color:#8b949e;margin-bottom:16px;font-size:0.9em">IOCs seen on 3+ nodes indicate broader campaigns with high confidence.</p>`)

	if len(corrs) > 0 {
		b.WriteString(`<table><thead><tr><th>IOC</th><th>Nodes</th><th>Confidence</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>`)
		for _, c := range corrs {
			ioc, _ := c["ioc"].(string)
			count, _ := c["node_count"].(float64)
			conf, _ := c["confidence"].(float64)

			clr := "#8b949e"
			if conf >= 0.8 {
				clr = "#f85149"
			} else if conf >= 0.6 {
				clr = "#d29922"
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

func confBar(pct float64, count int) string {
	clr := "#3fb950"
	if pct > 75 {
		clr = "#3fb950"
	} else if pct > 50 {
		clr = "#d29922"
	} else {
		clr = "#f85149"
	}
	return fmt.Sprintf(`<div class="stat-bar"><div class="stat-bar-fill" style="width:%.0f%%;background:%s"></div></div>`, pct, clr)
}

func jsStr(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func confBarVisual(conf float64) string {
	cls := "conf-low"
	clr := "#3fb950"
	pct := conf * 100
	if conf >= 0.7 {
		cls = "conf-high"
		clr = "#f85149"
	} else if conf >= 0.4 {
		cls = "conf-med"
		clr = "#d29922"
	}
	return fmt.Sprintf(`<div class="conf-bar %s"><div class="conf-fill" style="width:%.0f%%;background:%s"></div></div>`, cls, pct, clr)
}

func filterClass(status, current string) string {
	if status == current || (status == "" && current == "") {
		return " active"
	}
	return ""
}

func statusColor(compl, fail, run int) string {
	if fail > 0 {
		return "#f85149"
	}
	if run > 0 {
		return "#d29922"
	}
	return "#3fb950"
}

func init() {
	_ = time.Now
	_ = json.Marshal
}
