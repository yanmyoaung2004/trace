# Trace — Project Status, Working Features & Usage Guide

> Date: 2026-09-21. Code root `dev/`. Detail: `yma/AUDIT.md` (findings), `yma/FIX_PLAN.md` (P0→P3 plan + Wave A log), `yma/FOLLOWUPS_PLAN.md` (Wave A execution plan).
> Verified: `CGO_ENABLED=0 go build ./...` clean · `go vet ./...` clean except pre-existing `etw_windows.go:250 unsafe.Pointer` · `go test ./... -short` zero `FAIL`.

---

## 1. What stage is this project?

**Stage: working single-node beta on a trusted network. Not internet-facing, not multi-tenant prod.**

Think of it as: a security workstation + one server + a few agents that you run yourself. It investigates, detects, stores, and contains — with approvals and audit. It is past prototype (real storage engine, real auth, real tests) but before production operations (no Linux CI gates run yet, no signing ceremony executed, no hosted multi-org).

| Layer | Stage | Meaning for you |
| ----- | ----- | --------------- |
| Investigate (CLI + playbooks + intel) | Working | Run today, no server needed |
| Detect (SIEM + YARA/PE + TI) | Working | Run today with `--siem` |
| Store (TSE hot SQLite → Parquet) | Working | Run today with `--tse` |
| Server + dashboard + API | Working, authed | Run today on localhost/trusted LAN with Bearer keys |
| Fleet (`trace-agent` → server) | Working (just unblocked) | Enroll with provision token, then events flow |
| Respond (block/quarantine/kill + approvals) | Working, gated | Destructive steps wait for your approval |
| Audit | Working | Every mutation writes a chained row you can query/verify |
| Updates/installers | Fail-closed code, ceremony open | Refuses unsigned/tampered/downgraded; you still must provision keys |
| Backups/disk/rotation | Code done, ops open | Enforce 95% works; schedule + drill restores yourself |
| Asset/risk/reporting/correlation | Additive v1 landed | Inventory + scores + CSV/CEF + entity graph exist; not yet wired into every screen |
| Multi-tenant prod, internet exposure, `run_script` fleets | NOT ready | Needs Linux gates + ceremony + tagged push first |

---

## 2. System map in one picture

```text
You (CLI / dashboard)
  │  trace investigate | trace serve | trace server | trace-agent
  ▼
Dispatch (heuristic + optional LLM planner)
  ▼
Playbooks (YAML: file-analysis, hash-lookup, ip-enrich, block-ip, ...)
  ├─► Sift:      YARA + PE + hash cache + VirusTotal + rootkit
  ├─► Archive:   MITRE + CVE + IOC intel + web search
  ├─► Response:  block_ip / quarantine / kill / restart  (argv-only, approval-gated)
  └─► TI:        AbuseIPDB / OTX / Splunk / Elastic (config-wired keys)
  ▼
SIEM engine (--siem: files + syslog → decoders → rules → alerts → auto-case + auto-playbook)
  ▼
TSE storage (--tse: SQLite hourly hot → flusher → Parquet cold + manifest → router queries)
  ▼
Server (:8080 API + dashboard, Bearer auth, tenant-scoped, paginated) ◄── trace-agent fleet (provision-token enroll)
  ▼
Cases + hunts + approvals + audit log + compliance/asset reports + notifiers
```

Two binaries, one repo: `trace` (CLI/daemon/server) + `trace-agent` (endpoint sensor + executor). Same `dev/` Go module. SQLite-first, Parquet for history, no external DB required.

---

## 3. Working features, with simple examples

All commands run from `dev/` (PowerShell shown; `.\trace.exe`; on Linux use `./trace`).

### 3.1 Build + first health check

```powershell
go build -o trace.exe ./cmd/trace
go build -o trace-agent.exe ./cmd/trace-agent
.\trace.exe version
.\trace.exe config check              # validates config + precedence TRACE_* > flag > file > DB > default
.\trace.exe config dump --effective   # merged view, secrets redacted
```

What it proves: binaries build, config loader + `Validate()` works.

### 3.2 Investigate anything (no server needed)

```powershell
# Hash triage (Mimikatz SHA256 — expect malicious, confidence ~0.95)
.\trace.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# File analysis (EICAR test string — expect YARA hit, safe by design)
"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" | Out-File -Encoding ascii eicar.txt
.\trace.exe investigate --playbook file-analysis --param path=.\eicar.txt

# IP / domain enrichment (AbuseIPDB + OTX + VT when keys set, local intel otherwise)
.\trace.exe investigate --playbook ip-enrich --param ip=185.220.101.24
.\trace.exe investigate --playbook domain-reputation --param domain=evil.com

# History + report
.\trace.exe history
.\trace.exe report <investigation-id>
.\trace.exe report <investigation-id> -o report.md
```

What's happening: Dispatch picks the playbook (or LLM planner if configured) → Sift scans (YARA/PE/hash/VT) → Archive enriches (MITRE/CVE/IOC) → report with confidence + evidence + remediation.

### 3.3 Threat intel + MITRE/CVE lookups

```powershell
.\trace.exe investigate "tell me about T1566" --technique T1566        # phishing technique + mitigations
.\trace.exe investigate "check cve" --cve-id CVE-2024-3094             # severity, CVSS, products (needs internet)
```

Single store now: `intel/seed-iocs.json` (exact + CIDR, no substring false positives); `sift/hash.go` dup deleted.

### 3.4 SIEM live detection (`--siem`)

```powershell
.\trace.exe serve --siem --log-dir .\logs
# in another shell, trigger a rule:
Add-Content -Path ".\logs\access.log" -Value '10.0.0.5 - - [18/Jul/2026:12:00:00 +0000] "GET /admin HTTP/1.1" 500 100'
# expect within seconds: SIEM ALERT [HTTP_5XX_ERROR] + auto-investigation + auto-case (sev>=4)
```

Engine: 9 decoders → precompiled rules + worker pool → per-(rule,entity) suppression (no cross-host bleed) → 5-min dedup → alert → playbook + notifier fan-out.

### 3.5 Long-term storage (`--tse`)

```powershell
.\trace.exe serve --tse
.\trace.exe tse status     # watermark, hot/cold counts, errors
.\trace.exe tse flush      # force SQLite → Parquet now
.\trace.exe tse inspect    # Parquet files in manifest
.\trace.exe tse metrics    # enqueue/write/flush/drop + disk
.\trace.exe tse snapshot --storage-path ~/.trace/tse -o backup.tar.gz
```

Pipeline: bounded queue (segments, DLQ) → hourly SQLite (NORMAL, indexed, hour-split) → deterministic flusher → ZSTD Parquet + manifest commit → router merges hot+cold with UUIDv7 dedup. Retention drops tables only behind watermark + window; TTL expires only fully-old files; disk refuses writes at 95% (warns 85%).

### 3.6 Server + dashboard + API (authed)

```powershell
.\trace.exe server --http-addr :8080
# first boot writes ONCE, 0600, never prints: ~/.trace/data/admin_api_key
$env:TRACE_API_KEY = (Get-Content ~/.trace/data/admin_api_key)

curl -H "Authorization: Bearer $env:TRACE_API_KEY" http://localhost:8080/healthz
curl -H "Authorization: Bearer $env:TRACE_API_KEY" http://localhost:8080/api/v1/nodes
curl -H "Authorization: Bearer $env:TRACE_API_KEY" "http://localhost:8080/api/v1/investigations?limit=20"
# dashboard: http://localhost:8080/  (login via key; ?api_key= is REJECTED by design)
```

Trust model: provision-token enroll, server-assigned org, ctx-bound agent IDs, per-route perms + read-only scope matrix, tenant predicates everywhere, cursor pagination, idempotency keys, `{data,error,code,request_id}` envelope, honest `/readyz` (503 when DB/TSE/disk down).

### 3.7 Fleet: enroll an agent, see events, dispatch response

```powershell
# 1. mint a single-use token (24h) for your org
.\trace.exe admin token mint <org-id>     # prints token ONCE

# 2. enroll the endpoint (token-only; client api_key is rejected)
.\trace-agent.exe --server http://127.0.0.1:8080 --provision-token <tok> --verbose

# 3. server side: list, view, stream events
.\trace.exe edr list
.\trace.exe edr view <agent-id>
.\trace.exe edr events <agent-id> --type alert --min-severity 3 --limit 10

# 4. dispatch a contained action (allowlisted type + approval + audit)
.\trace.exe edr dispatch <agent-id> block_ip --ip 203.0.113.42
.\trace.exe edr dispatch <agent-id> quarantine_file --path C:\mal.exe
.\trace.exe edr dispatch <agent-id> kill_process --pid 4521
.\trace.exe edr dispatch <agent-id> isolate_host
.\trace.exe edr dismiss <alert-id> --reason "legit admin activity"
.\trace.exe edr revoke <agent-id>
```

Guards: argv-only executors (no `sh -c` with variables), `run_script` deny-by-default (needs flag + signed policy + approval), no client-side `chain`, structured rollback (legacy strings never execute), per-step approval tokens (nonce + step + identity + expiry).

### 3.8 Approvals (human gate on destruction)

```powershell
.\trace.exe approval pending          # token-bound queue (nonce, step, action, expiry)
.\trace.exe approval approve <id> --token <token-json> --approver you
.\trace.exe approval deny <id> --token <token-json> --approver you
# every destructive playbook (block-ip, quarantine-file, kill-process, restart-service, edr-isolate/kill) carries wait: analyst_approval
```

Expired/foreign tokens deny closed. Every grant/deny writes an audit row.

### 3.9 Cases, hunts, compliance, assets

```powershell
# Cases (state machine open→investigating→resolved→closed, ack/assign, paginated)
.\trace.exe case create --title "phishing wave" --severity high
.\trace.exe case list --status open
.\trace.exe case view <id>
.\trace.exe case note <id> "contained host-42, blocked 185.220.101.24"
.\trace.exe case ioc <id> --type ip --value 185.220.101.24
.\trace.exe case export <id> --format json     # also csv, cef (new)
.\trace.exe case export-pdf <id>

# Hunts (scheduled proactive checks, CAS-claimed, pooled)
.\trace.exe hunt create --name check-log4j --playbook hash-lookup --param hash=... --schedule "0 */6 * * *"
.\trace.exe hunt list
.\trace.exe hunt run check-log4j

# Compliance (8 frameworks, SCA + rules + manual assessments + evidence)
.\trace.exe compliance frameworks
.\trace.exe compliance report --framework pci_dss_v4.0
.\trace.exe compliance report --framework hipaa -o hipaa-report.html
.\trace.exe compliance assess --framework gdpr --control Art.32 --status pass --notes "AES-256 in use"
.\trace.exe compliance report --framework nist_sp_800-53 --format csv   # csv|cef new

# Assets + risk (new additive package)
.\trace.exe asset list --format table
.\trace.exe asset list --min-risk 70 --format json
```

### 3.10 Audit, config, updates, plugins

```powershell
# Audit trail (chained HMAC incl. Details, persisted 0600 key, paged verify)
# via API: GET /api/v1/audit?resource=cases&since=7d  (Bearer, PermAuditRead)

# Config lifecycle
.\trace.exe config check
.\trace.exe config dump --effective
.\trace.exe config migrate --config <path>

# Updates (fail-closed: HTTPS-only, SHA mandatory, sig-when-keyed, semver, safe swap)
.\trace.exe update self
.\trace.exe update intel
.\trace.exe update playbooks

# Plugins (pinned registry, checksum + signature, explicit confirm)
.\trace.exe plugin list
.\trace.exe plugin install <name-or-url> --sha256 <hex> [--sig <b64>]
```

### 3.11 TUI + completions

```powershell
.\trace.exe                       # full-screen: Dashboard / Investigations / Cases / SIEM / Config (Tab, arrows, Enter, q)
trace completion powershell | Out-String | Invoke-Expression   # tab-complete playbooks, cases, hunts
```

---

## 4. What is NOT working yet (honest list)

| # | Item | Status | What you must do instead |
| - | ---- | ------ | ------------------------ |
| 1 | Real ghcr image digest | Placeholder `0000` in daemonset | Replace after first tagged push |
| 2 | Signing-key ceremony | Code ready, keys not provisioned | Gen offline keypair → set `TRACE_UPDATE_SIGNING_KEY` + `TRACE_UPDATE_VERIFY_KEY_HEX` → dual-publish `.sha256`+`.sig` one release → enforce |
| 3 | `-race`, kill-9/soak/stress/malware/e2e, DuckDB CGO gates | Deferred — Windows MinGW here has no 64-bit cgo | Run on CI/Linux |
| 4 | Multi-tenant prod sharing | Predicates + backfill done, needs your tenant-A/B test | Verify isolation yourself before sharing one server |
| 5 | Internet exposure | TLS optional, plaintext warns | Terminate TLS, never expose `:8080` raw |
| 6 | `run_script` fleets | Deny-by-default, needs flag + signed policy + approval | Keep denied unless you sign + approve each run |
| 7 | Scheduled reporting cadence, full entity-graph UI | Code exists (schedule.go, correlation.go, riskpanel), not wired into every screen | Use CLI flags (`--format`, `asset list`) for now |
| 8 | Docs drift | `user-guide`/`deployment-guide` predate the auth change | Trust code + this file; guides need a refresh pass |

---

## 5. Suggested path (smallest safe rollout)

1. **Today (30 min):** build → `config check` → one `investigate` → `server` → mint token → enroll one test host → `edr list/events`.
2. **This week:** signing ceremony → tagged push (digest + ruleset pin) → Linux CI green → TLS on → backup `~/.trace` scheduled.
3. **Next:** one approval-gated containment drill (`block-ip` → approve → verify → audit row) → expand to a second host → scheduled hunts + weekly compliance report.
4. **Later:** tenant-A/B isolation test → second org → consider wider rollout. Keep `run_script` denied.

If anything above fails, the file to open first is the one named in the error: `yma/AUDIT.md` for why, `yma/FIX_PLAN.md` for what was done, `yma/FOLLOWUPS_PLAN.md` for what remains.
