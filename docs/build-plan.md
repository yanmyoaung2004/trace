# Trace — Build Plan

## Phase 0 — Project scaffold (days 1–2)

**Goal**: Go module ready to build.

- `go mod init github.com/<you>/innoigniter`
- Directory structure
- CI: `go build`, `go vet`, `go test ./...`
- `Makefile` with common commands
- `cmd/innoigniter/main.go` — entrypoint
- `internal/` — all packages private
- `playbooks/` — YAML playbook directory
- `intel/` — bundled SQLite DB with MITRE + CVE seed data

```
innoigniter/
├── cmd/innoigniter/main.go
├── internal/
│   ├── agent/        # Agent interface
│   ├── playbook/     # Playbook engine
│   ├── host/         # Host Agent
│   ├── knowledge/    # Knowledge Agent
│   ├── detection/    # Detection Agent
│   ├── siem/         # SIEM engine
│   ├── db/           # SQLite schema + queries
│   ├── taskqueue/    # Task queue
│   ├── plugin/       # Plugin loader
│   └── log/          # Investigation log
├── intel/            # Bundled DB + YARA rules
├── playbooks/        # Built-in playbooks
├── Makefile
└── go.mod
```

---

## Phase 1 — Foundation (days 3–7)

**Goal**: Backbone operational — schema, task queue, agent interface, CLI skeleton.

- SQLite schema: `tasks`, `investigations`, `results`, `cache`, `config`, `events`
- WAL mode, migrations on startup
- Agent interface definition
- Task queue with polling loop (agents check `tasks` table, claim work by status update)
- File-based communication layer (agent writes result, Host reads when ready)
- Config loader (JSON/YAML file, env var override)
- CLI skeleton (`cobra`): `serve`, `investigate`, `status`, `history`
- Append-only JSONL investigation log writer
- Logger (structured, level-based)

```go
type Agent interface {
    Name() string
    Capabilities() []Capability
    Execute(ctx context.Context, input Input) (Output, error)
}

type Capability struct {
    Action   string
    Inputs   []string
    Outputs  []string
}
```

**Verification**: `innoigniter serve` starts, agents register, SQLite initializes, CLI responds.

---

## Phase 2 — Playbook engine (days 8–14)

**Goal**: YAML playbooks execute end-to-end with conditional steps, variable interpolation, and HITL.

- YAML playbook parser
- DAG executor (linear, conditional with `if:`, parallel with `foreach:`)
- Variable interpolation: `${input.xx}`, `${result.xx}`, `${outputs.agent.action.xx}`
- Timeout per step, overall deadline per investigation
- Retry with configurable backoff
- HITL pause/resume — step blocks on `tasks` status change from analyst
- Error handling — failed step marks investigation failed unless `optional: true`
- Playbook library directory auto-loaded at startup

**Built-in playbooks**:
- `hash-lookup` — check hash against cache + YARA + VT
- `file-analysis` — extract PE metadata, YARA scan, VT lookup
- `ip-reputation` — check IP against cache + VT + threat intel
- `url-scan` — extract URL indicators, check reputation
- `process-investigation` — process name → known malware → MITRE mapping
- `alert-triage` — generic alert → enrich IOCs → severity → report

**Verification**: `innoigniter investigate --playbook hash-lookup --param hash=<sha256>` runs the full DAG and prints a report.

---

## Phase 3 — Knowledge Agent (days 15–21)

**Goal**: Enrich indicators with MITRE ATT&CK, CVE context, and threat intel.

- MITRE ATT&CK DB bundled via `embed` (techniques, tactics, sub-techniques, software, groups)
- CVE lookup: local cache first, NVD API fallback (rate-limited)
- Threat intel cache with configurable TTL per source
- Agent plugin implementing `Agent` interface:
  - `mitre_lookup` — map technique ID or name → full description + tactics + mitigations
  - `cve_lookup` — CVE ID → severity, CVSS, affected products, exploitability
  - `malware_lookup` — malware family → ATT&CK mapping, known aliases, behaviors
  - `ioc_enrich` — enrich a hash/IP/domain with all available intel
- Web search tool for open-source threat intel (configurable provider)
- RAG pipeline: embed intel documents → store in SQLite vec table → semantic search

**Verification**: `innoigniter investigate --playbook ioc-enrich --param ioc=<value>` enriches with MITRE + CVE knowledge.

---

## Phase 4 — Detection Agent (days 22–28)

**Goal**: Analyze files and URLs locally before reaching for cloud APIs.

- YARA scanner (embed rules, compile on startup, scan by path or bytes)
- PE file parser (sections, imports/exports, compile timestamp, entropy, packer detection)
- Hash calculator (MD5, SHA1, SHA256)
- Hash reputation: local SQLite cache lookup, TTL-based expiry
- VirusTotal client (hash lookup, URL lookup, domain lookup, batch + rate-limit)
- Agent plugin implementing `Agent` interface:
  - `yara_scan` — scan file path against all rules, return matched rule names + metadata
  - `pe_analyze` — parse PE, return metadata + suspicious indicators
  - `hash_lookup` — check hash against local cache, optionally VT
  - `vt_lookup` — hash/URL/domain → VT report with detection ratio + vendor labels
  - `file_analyze` — combo: hash + YARA + PE + VT in one step

**Verification**: `innoigniter investigate --playbook file-analysis --param file=<path>` produces detection verdict with confidence score.

---

## Phase 5 — Host Agent (days 29–35)

**Goal**: Single command to investigate anything — intent parsing, playbook matching, report generation. **MVP complete.**

- Intent parser: classify user request into investigation type
  - "check this file" → `file-analysis`
  - "what is this IP" → `ip-reputation`
  - "analyze this URL" → `url-scan`
  - "check this hash" → `hash-lookup`
  - "investigate this alert" → `alert-triage`
  - fallback → LLM planner
- Playbook matcher: map intent to best playbook by keyword + parameter matching
- LLM planner (fallback): decompose novel intent into ad-hoc steps, route to agents
- Report synthesizer: collect agent outputs → merge → confidence calibration → structured report
- Investigation lifecycle: create, dispatch, track, complete, archive
- Markdown report with: summary, indicators, MITRE mapping, confidence, evidence, timeline, remediation

**Verification**: `innoigniter investigate "check this file" --file malware.exe` → playbook matches → agents execute → report printed. End-to-end.

---

## Phase 6 — SIEM engine (days 36–49)

**Goal**: Watch logs in real time, apply rules, generate alerts that trigger playbooks.

- File watcher: platform-specific (`inotify` on Linux, `ReadDirectoryChangesW` on Windows, `kqueue` on macOS)
- Syslog listener: UDP + TCP on configurable port
- Log decoder framework:
  - Raw string → structured event via decoder chain
  - Built-in decoders: JSON, syslog (RFC 3164 + 5424), CSV, EVTX (Windows), Apache/Nginx combined
  - Custom decoder interface: `Decode(raw []byte) → *Event`
- Normalized event schema
- YAML rule engine:
  - Match conditions: field equality, regex, numeric comparison, CIDR matching
  - Windowed correlation: "5 failed logins from same source IP in 60 seconds"
  - Suppression: same alert max once per N minutes per source
  - Action: create alert → feed to Host Agent → trigger playbook
- Alert schema: ID, title, severity, MITRE mapping, event IDs, evidence JSON, timestamp
- SIEM enable/disable via config flag (opt-in)

**Built-in rules**:
- Multiple failed logins (SSH, RDP, Windows Event 4625)
- Suspicious process execution (cmd.exe spawning PowerShell, rundll32, regsvr32)
- File changes in sensitive directories (/etc, %SYSTEMROOT%)
- Known-bad hash detection via YARA on new files

**Verification**: `innoigniter serve --siem` starts file watcher, decodes log, detects 5 auth failures from same IP, creates alert, triggers `ip-reputation` playbook.

---

## Phase 7 — Response actions (days 50–56)

**Goal**: Playbooks can act, not just analyze — with HITL safety.

- Response Agent implementing `Agent` interface
- OS-level actions:
  - `block_ip` — iptables (Linux), Windows Firewall, pf (macOS)
  - `quarantine_file` — move to restricted directory with ACL change
  - `kill_process` — by PID or name
  - `restart_service` — systemctl (Linux), sc (Windows)
  - `add_firewall_rule` — allow/block port, protocol, direction
- All actions record: who triggered, what was done, timestamp, original state for rollback
- Rollback capability — store undo commands per action, expose `innoigniter rollback <action-id>`
- HITL approval: playbook step with `wait: analyst_approval` blocks until analyst confirms or denies
- CLI: `innoigniter approval pending`, `approve <id>`, `deny <id>`

**Verification**: Phishing playbook runs → detection extracts malicious domains → playbook pauses → `innoigniter approval pending` → sees domain block request → `approve` → Response Agent blocks via iptables.

---

## Phase 8 — Plugins (days 57–63)

**Goal**: Every extension point has a working plugin interface and at least one example.

- Plugin loader: gRPC sidecar process (language-agnostic) or compiled-in
- Plugin registry: capabilities declared → matched to agent routing at runtime
- Reference plugins:
  - SIEM connector: Splunk → poll saved search → normalize → feed as alert
  - LLM provider: OpenAI GPT-4 → implement `Planner` interface
  - Threat intel feed: STIX/TAXII → fetch → normalize → merge into local intel DB
  - Exporter: HTML report → serve as local web page
- `innoigniter plugin install <name>` — download plugin binary to `~/.innoigniter/plugins/`
- `innoigniter plugin list` — show installed + their capabilities

**Verification**: `innoigniter plugin install inno-splunk` → SIEM connector appears in capabilities → Splunk alerts trigger investigations.

---

## Phase 9 — Central server (days 64–77)

**Goal**: Optional central binary for team deployment with aggregation and dashboard.

- Same Go binary, server mode via `innoigniter server` (different config)
- Edge sync protocol (gRPC + TLS):
  - Edge registers with server (heartbeat every 30s)
  - Edge pushes investigation summaries + full reports
  - Server pulls from disconnected edges on reconnect
- Server aggregates:
  - Investigation DB (PostgreSQL or SQLite)
  - Cross-node correlation: same IOC seen at 3+ edges → higher confidence
  - Long-term retention: configurable retention policy
- Team dashboard: web UI (minimal, read-only)
  - Investigation list with status, severity, source edge
  - Search by IOC, agent, date range
  - Investigation detail with timeline + report
- RBAC: admin, analyst, viewer
- User management: invite via email, password or SSO, API keys
- Server is opt-in. Edge mode works identical without it.

**Verification**: Two edge nodes → both send investigations to server → server dashboard shows cross-node view.

---

## Phase 10 — Polish (days 78–84)

**Goal**: Ready for real users.

- Update system: `innoigniter update` downloads signed binary, verifies signature, swaps atomically. `innoigniter update-intel` refreshes intel DB. `innoigniter update-playbooks` fetches latest playbook library.
- Release pipeline: GitHub Actions builds for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64. Signs with GPG or cosign.
- First-run experience: `innoigniter init` — prompts for VT API key (optional), LLM provider URL+key (optional), SIEM enable (optional). Creates config file.
- Documentation: README.md with quickstart, docs/ with CLI reference, playbook authoring guide, plugin development guide.
- Telemetry: opt-in, privacy-first. Reports: version, OS, active plugin count, investigation count. No content.
- Web UI: optional companion (served by binary), read-only dashboard — investigation list, search, report viewer.

---

## Timeline

| Phase | Duration | Cumulative | Delivers |
|---|---|---|---|
| 0 — Scaffold | 2 days | 2 days | Repo, build, CI |
| 1 — Foundation | 5 days | 7 days | Backbone, CLI, agent interface |
| 2 — Playbook engine | 7 days | 14 days | DAG runner, playbook library |
| 3 — Knowledge Agent | 7 days | 21 days | MITRE, CVE, intel enrichment |
| 4 — Detection Agent | 7 days | 28 days | YARA, PE, VT analysis |
| **5 — Host Agent** | **7 days** | **35 days** | **MVP — end-to-end investigation** |
| 6 — SIEM engine | 14 days | 49 days | Log ingestion + rules |
| 7 — Response actions | 7 days | 56 days | SOAR loop closed |
| 8 — Plugins | 7 days | 63 days | Extensibility |
| 9 — Central server | 14 days | 77 days | Team deployment |
| 10 — Polish | 7 days | 84 days | Production readiness |
