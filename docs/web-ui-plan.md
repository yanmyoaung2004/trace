# Web UI Dashboard Plan

## What exists

The `trace server` command already serves a dashboard at `/` with:
- Navigation bar with Dashboard / Investigations / Cases / Correlations tabs
- Investigation list with search + status filter
- Investigation detail with timeline
- Cases page
- Correlations page
- Live data API at `/api/live`
- Dark theme, responsive layout

## What's missing

| Feature | Why it matters |
|---------|---------------|
| **TSE status widget** | Shows watermark, event counts, disk usage — operators need this |
| **SIEM alert timeline** | Real-time view of alerts as they fire |
| **Stats on index page** | Total investigations, open cases, active hunts, alert count |
| **Better active tab** | Current navigation doesn't highlight the active page |

## Implementation plan

### Task 1: TSE status endpoint + widget (3h)

- Add `/api/tse` endpoint that returns TSE metrics as JSON
- Read metrics from `metrics.Global.Snapshot()` + disk check
- Add TSE stat card to the dashboard index page
- Auto-refresh every 10s via `fetch('/api/tse')`

### Task 2: SIEM alert timeline page (4h)

- Add `/alerts` route to dashboard handler
- Query alerts from the database (last 100, newest first)
- Render as a timeline with severity badge + timestamp + title + rule ID
- Add filter by severity (ALL / INFO / WARN / CRITICAL)

### Task 3: Stats on index page (2h)

- Count investigations, cases, hunts from the database
- Display as stat cards at the top of the index page
- Auto-refresh via API calls

### Task 4: Active tab highlighting (1h)

- Read the current URL path
- Highlight the matching nav item
- Works for all pages: `/`, `/investigations/`, `/cases`, `/alerts`, `/correlations`

## Design

All server-rendered HTML with inline CSS (matching existing pattern). No JavaScript frameworks. `fetch()` only for live-updating widgets.

Color palette matches the landing page dark theme (oklch-based).

Navigation structure:
```
[Dashboard] [Investigations] [Cases] [Si警 Alerts] [Correlations]
```

## Effort

| Task | Hours |
|------|:-----:|
| 1. TSE status endpoint + widget | 3 |
| 2. SIEM alert timeline page | 4 |
| 3. Index page stats | 2 |
| 4. Active tab highlighting | 1 |
| **Total** | **10** |
