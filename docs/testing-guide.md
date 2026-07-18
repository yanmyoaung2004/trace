# Testing Guide

## Prerequisites

```powershell
cd dev
go build -o trace.exe .\cmd.trace\
```

All commands below assume you're in the `dev/` directory.

---

## Phase 0 — Project scaffold

```powershell
go build ./...
go vet ./...
.\trace.exe version
```
Expected: .trace v0.1.0-dev`

```powershell
go test ./... -count=1
```
Expected: all packages pass.

---

## Phase 1 — Foundation

```powershell
# Serve starts and registers agents
.\trace.exe serve
```
Expected: logs `3 plugins loaded`, graceful shutdown on Ctrl+C.

```powershell
# Run tests with coverage for all foundation packages
go test ./internal/db/... ./internal/config/... ./internal/taskqueue/... ./internal/investigation/... -v -count=1
```
Expected: DB migrations, task enqueue/claim/complete/fail, config file+env loading, investigation CRUD, log writing all pass.

---

## Phase 2 — Playbook engine

```powershell
# Run a playbook by name
.\trace.exe investigate "check this hash" --playbook hash-lookup --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```
Expected: Investigation created, all 5 playbook steps execute, report shows `reputation: unknown` (hash lookup), `count: 0` (YARA), MITRE mappings from IOC enrich.

```powershell
# Intent classification
.\trace.exe investigate "analyze this file" -f test.exe
```
Expected: Auto-selects `file-analysis` playbook.

```powershell
# Conditional step skipping
# (Tested via unit test)
go test ./internal/playbook/... -run TestExecutorConditional -v
```

```powershell
# HITL approval workflow
# Start investigation that pauses for approval, then approve:
.\trace.exe approval pending
.\trace.exe approval approve <investigation-id>
```

---

## Phase 3 — Archive Agent

```powershell
# MITRE technique lookup
.\trace.exe investigate "tell me about T1566" --technique T1566
```
Expected: Returns Phishing technique with description, mitigations, detection, platforms, tactics.

```powershell
# Sub-technique lookup
.\trace.exe investigate "lsass memory" --technique T1003.001
```
Expected: Returns LSASS Memory sub-technique with Credential Guard mitigations.

```powershell
# IOC enrichment (known Mimikatz hash)
.\trace.exe investigate "check hash" --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```
Expected: IOC enrich returns `builtin_match: true`, `reputation: malicious`, `confidence: 0.95`, tags `["mimikatz", "credential-access"]`.

```powershell
# CVE lookup (requires internet)
.\trace.exe investigate "check cve" --cve-id CVE-2024-3094
```
Expected: CVE data with severity, CVSS score, description, affected products. Falls back gracefully if NVD is unreachable.

```powershell
# Malware family lookup
# Currently returns MITRE mappings for the search term
.\trace.exe investigate "mimikatz" --playbook mitre-lookup --technique T1003.001
```

```powershell
# Unit tests
go test ./internal/knowledge/... -v -count=1
```
Expected: MITRE DB loading, search, sub-technique lookup, IOC enrichment with cache, CVE error handling all pass.

---

## Phase 4 — Sift Agent

```powershell
# YARA scan on a file (use a test file)
echo "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" > eicar.txt
.\trace.exe investigate "scan file" --playbook file-analysis -f .\eicar.txt
```
Expected: YARA matches EICAR test pattern, PE analysis reports "not a PE file", hash lookup runs.

```powershell
# PE analysis on a real PE file
.\trace.exe investigate "analyze pe" --playbook file-analysis -f C:\Windows\System32\notepad.exe
```
Expected: PE metadata (sections, imports, timestamps), YARA scan, hash reputation.

```powershell
# VT lookup (requires VT API key via TRACE_VT_API_KEY env var)
$env:TRACE_VT_API_KEY = "your-key"
.\trace.exe investigate "check hash vt" --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```
Expected: VT reports detection ratio and vendor labels. Falls back to local cache if VT is unreachable.

```powershell
# VT rate limit handling
# Run multiple lookups in quick succession — tests queue + backoff
```

```powershell
# Unit tests
go test ./internal/detection/... -v -count=1
```

---

## Phase 5 — Dispatch Agent (MVP)

```powershell
# Full end-to-end: file analysis with automatic playbook selection
.\trace.exe investigate "check this file" -f C:\Windows\System32\notepad.exe
```
Expected: Intent classifier picks file-analysis, all agents execute, consolidated report with confidence score.

```powershell
# Full end-to-end: hash lookup
.\trace.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```
Expected: Intent classifier extracts hash from query, runs hash-lookup playbook.

```powershell
# Investigation history and status
.\trace.exe serve  # in one terminal
# In another:
# Query the investigation log in .trace/logs/
```

---

## Phase 6 — SIEM engine

```powershell
# Start SIEM engine with config (watches logs\ dir, syslog on :9514)
.\trace.exe serve --config config.json
```
Expected: File watcher polls `logs\` every 5s, syslog UDP+TCP listeners on :9514.

```powershell
# Generate HTTP 500 error event (triggers HTTP_5XX_ERROR alert + auto-investigation)
Add-Content -Path "logs\access.log" -Value '10.0.0.5 - - [18/Jul/2026:12:00:00 +0000] "GET /admin HTTP/1.1" 500 100'
```
Expected within 5s: SIEM ALERT log with `HTTP_5XX_ERROR` rule, followed by `investigation completed — 5 results`.

```powershell
# Generate multiple auth failures (correlation: 5 in 60s → MULTIPLE_FAILED_LOGINS)
# Run these 5 in rapid succession:
1..5 | ForEach-Object {
  Add-Content -Path "logs\syslog.log" -Value "<34>Jul 18 12:00:00 server sshd[$_]$(Get-Random): Failed password for root from 10.0.0.5 port 22 ssh2"
}
```
Expected: `MULTIPLE_FAILED_LOGINS` alert with MITRE `T1110.003` after 5th event.

```powershell
# Test Apache decoder with different HTTP statuses
Add-Content -Path "logs\access.log" -Value '192.168.1.1 - - [18/Jul/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
Add-Content -Path "logs\access.log" -Value '192.168.1.1 - - [18/Jul/2026:12:00:01 +0000] "GET /login HTTP/1.1" 401 56'
Add-Content -Path "logs\access.log" -Value '10.0.0.5 - - [18/Jul/2026:12:00:02 +0000] "POST /api HTTP/1.1" 500 200'
```
Expected: 200→tagged `http_success`, 401→`http_client_error`, 500→`http_error` + alerts.

```powershell
# Test JSON log decoder
Add-Content -Path "logs\app.log" -Value '{"timestamp":"2026-07-18T12:00:00Z","event":"login","user":"admin","severity":3}'
```

```powershell
# Syslog test via UDP (requires nc or PowerShell UDP socket)
$udp = New-Object System.Net.Sockets.UdpClient
$bytes = [System.Text.Encoding]::ASCII.GetBytes("<34>Jul 18 12:00:00 test sshd[1234]: Failed password from root from 10.0.0.5 port 22 ssh2")
$udp.Send($bytes, $bytes.Length, "127.0.0.1", 9514)
$udp.Close()
```

```powershell
# Unit tests
go test ./internal/siem/... -v -count=1
```
Expected: 8 tests (JSON, Apache, syslog auth, file watcher, correlation, raw, multiple decoders, high volume).

---

## Phase 7 — Response actions

```powershell
# Block an IP address (uses netsh/iptables/pfctl depending on OS)
.\trace.exe investigate "block 10.0.0.5" --playbook block-ip --ip 10.0.0.5
```
Expected: Response agent records firewall rule, returns action_id + rollback command.
Note: Requires admin/root privileges on most systems.

```powershell
# Rollback an action by ID
.\trace.exe investigate "rollback previous action" --playbook rollback-action --action-id <action_id>
```

```powershell
# Quarantine a file (moves to restricted quarantine directory)
.\trace.exe investigate "quarantine eicar" --playbook quarantine-file -f .\eicar.txt
```
Expected: File moved to `%TEMP%.trace-quarantine\`, permissions set to read-only.

```powershell
# Kill a process by name
.\trace.exe investigate "kill process" --playbook kill-process --name notepad
```

```powershell
# Restart a service
.\trace.exe investigate "restart service" --playbook restart-service --name BITS
```

```powershell
# List all response actions in database
# (query via SQLite directly)
sqlite3 .trace\trace.db "SELECT id, action_name, target, status, created_at FROM response_actions ORDER BY created_at DESC LIMIT 10"
```

```powershell
# Unit tests
go test ./internal/response/... -v -count=1
```
Expected: 10 tests (block IP with/without target, quarantine missing file, kill process, restart service, rollback, all actions return ID, name, capabilities).

---

## Phase 8 — Plugins

### Build and unit tests

```powershell
go build -o trace.exe ./cmd.trace
go vet ./...
go test ./... -count=1
```
Expected: Build succeeds, vet clean, all tests pass.

### CLI commands

```powershell
# Version
.\trace.exe version
```
Expected: `Trace v0.1.0-dev`

```powershell
# List all registered agents + their capabilities
.\trace.exe plugin list
```
Expected: 5 agents shown with their actions (detection, knowledge, host, response, exporter).

```powershell
# Full end-to-end investigation with intent classification
.\trace.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```
Expected: Intent classifier maps to `hash-lookup` playbook, all steps execute, markdown report with `malicious` reputation (Mimikatz).

```powershell
# Investigation history
.\trace.exe history
```
Expected: Table of recent investigations with ID, status, intent, playbook, timestamp.

```powershell
# Investigation status
.\trace.exe status <investigation-id>
```
Expected: Full details for a single investigation.

```powershell
# Regenerate report for a completed investigation
.\trace.exe report <investigation-id>
```
Expected: Markdown report output.

```powershell
# Save report to file
.\trace.exe report <investigation-id> -o report.md
```
Expected: Report written to `report.md`.

### HTML report server (reference plugin)

```powershell
# Start daemon with exporter
.\trace.exe serve --export :8080
```
Expected: Logs `Report server started at http://:8080`. Open `http://localhost:8080` to see dark-themed investigation list with links to detail pages.

### HITL approval workflow

```powershell
# List investigations waiting for analyst approval
.\trace.exe approval pending
```
Expected: Table of investigations with `waiting_approval` status, or "No pending approvals."

```powershell
# Approve or deny a pending investigation step
.\trace.exe approval approve <investigation-id>
.\trace.exe approval deny <investigation-id>
```
Expected: Status updated to `approved` or `denied`.

### Plugin management

```powershell
# Install a plugin from URL
.\trace.exe plugin install https://plugins.trace.io/v1/plugins/my-plugin.so
```
Expected: Downloads `.so` to `~/.trace/plugins/`, logs size + path.

```powershell
# Remove an installed plugin
.\trace.exe plugin remove my-plugin.so
```
Expected: Plugin file deleted from plugins directory.

---

## Phase 9 — Central server

### Build and unit tests
```powershell
go build -o trace.exe ./cmd.trace
go vet ./...
go test ./... -count=1
```
Expected: Build succeeds, vet clean, all tests pass.

### Server mode (dashboard + sync API)

```powershell
# Terminal 1 — Start central server
.\trace.exe server --http-addr :8080
```
Expected: Logs `starting in server mode`, `HTTP API + dashboard on :8080`. Open `http://localhost:8080` for dashboard (investigation list, search, correlations).

```powershell
# Terminal 2 — Start edge node with sync
.\trace.exe serve --server-addr http://localhost:8080
```
Expected: Edge logs `registered as node <id>`, heartbeats every 30s, pushes investigations to server.

```powershell
# Terminal 2 — Run an investigation on the edge
.\trace.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```
Expected: Investigation appears on server dashboard at `http://localhost:8080` within 30s.

### API endpoints

```powershell
# List registered nodes
curl http://localhost:8080/api/v1/nodes
```

```powershell
# List investigations (with optional filters)
curl http://localhost:8080/api/v1/investigations
curl "http://localhost:8080/api/v1/investigations?search=mimikatz"
curl "http://localhost:8080/api/v1/investigations?status=completed"
```

```powershell
# Get a single investigation
curl http://localhost:8080/api/v1/investigations/<id>
```

```powershell
# Cross-node IOC correlations
curl http://localhost:8080/api/v1/correlations
```

### Cross-node correlation

```powershell
# Run the same hash on TWO different edge nodes (e.g. two machines, or with different config paths)
# On Node 1:
.\trace.exe serve --server-addr http://localhost:8080
.\trace.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# On Node 2:
.\trace.exe serve --server-addr http://localhost:8080
.\trace.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Check server dashboard → Correlations tab shows IOC with 2+ nodes, confidence 0.75+
```
Expected: Cross-node correlation page shows Mimikatz hash seen on 2+ nodes.

### RBAC + API key auth (admin setup)

```powershell
# Create an admin user (via DB)
sqlite3 .trace/trace.db "INSERT INTO server_users (id, email, password_hash, role, api_key) VALUES ('admin-1', 'admin@example.com', 'hash', 'admin', 'sk-xxxxxxxxxxxxx');"
```

```powershell
# Authenticated API call
curl -H "Authorization: Bearer sk-xxxxxxxxxxxxx" http://localhost:8080/api/v1/nodes
```

---

## Phase 10 — Polish

### Build and unit tests

```powershell
go build -o trace.exe ./cmd.trace
go vet ./...
go test ./... -count=1
```
Expected: Build succeeds, vet clean, all tests pass.

### First-run setup

```powershell
# Run the setup wizard
.\trace.exe init
```
Expected: Interactive prompts for VT key, LLM URL, web search key, SIEM, telemetry.
Creates `~/.trace/config.json`. Pressing Enter on all skips creates a minimal config.

```powershell
# Config file is created
type $env:USERPROFILE\.trace\config.json
```
Expected: JSON with default paths and any options you provided.

### Self-update

```powershell
# Check update command
.\trace.exe update self --help
```
Expected: Downloads the latest release binary from GitHub, verifies signature if available,
creates backup, performs atomic swap.

```powershell
# Update won't actually run without a release server — test the command structure
.\trace.exe update self
```
Expected: Fails gracefully (HTTP error or connection refused) — not a crash.

### Intel and playbook updates

```powershell
# Refresh intel database
.\trace.exe update intel --help
```

```powershell
# Fetch latest playbook library
.\trace.exe update playbooks --help
```
Expected: Both show usage. Download from release server when available.

### Cross-compile

```powershell
# Build for all platforms
make cross
```
Expected: 5 binaries created (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64).

### GitHub Actions CI

The `.github/workflows/` directory contains:
- `ci.yml` — build + vet + test + cross-compile on every push/PR
- `release.yml` — triggered by `v*` tags, builds all platforms, creates GitHub release with checksums

Check workflow syntax:
```powershell
# Go to repo root and validate YAML
# GitHub validates these server-side on push
```

### Telemetry

Telemetry is opt-in (enabled via `init` wizard or config `telemetry.enabled: true`).
Reports once on startup and every 24h: version, OS, arch, plugin count, investigation count, uptime.

```powershell
# Enable via config
# Add to ~/.trace/config.json:
# "telemetry": { "enabled": true }
```

### Documentation

Check that the following docs exist:
- `README.md` — quickstart, CLI ref, architecture, playbook list
- `docs/playbook-authoring.md` — YAML structure, fields, interpolation, conditions
- `docs/plugin-development.md` — Go plugin interface, build, install, distribution

## Quick smoke test (full pipeline)

```powershell
cd dev
go build -o trace.exe .\cmd.trace\
.\trace.exe version
.\trace.exe investigate "check T1566" --technique T1566
.\trace.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
go test ./... -count=1
```

If all three commands pass, the system is healthy.
