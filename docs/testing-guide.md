# Testing Guide

## Prerequisites

```powershell
cd dev
go build -o innoigniter.exe .\cmd\innoigniter\
```

All commands below assume you're in the `dev/` directory.

---

## Phase 0 — Project scaffold

```powershell
go build ./...
go vet ./...
.\innoigniter.exe version
```
Expected: `innoigniter v0.1.0-dev`

```powershell
go test ./... -count=1
```
Expected: all packages pass.

---

## Phase 1 — Foundation

```powershell
# Serve starts and registers agents
.\innoigniter.exe serve
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
.\innoigniter.exe investigate "check this hash" --playbook hash-lookup --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```
Expected: Investigation created, all 5 playbook steps execute, report shows `reputation: unknown` (hash lookup), `count: 0` (YARA), MITRE mappings from IOC enrich.

```powershell
# Intent classification
.\innoigniter.exe investigate "analyze this file" -f test.exe
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
.\innoigniter.exe approval pending
.\innoigniter.exe approval approve <investigation-id>
```

---

## Phase 3 — Knowledge Agent

```powershell
# MITRE technique lookup
.\innoigniter.exe investigate "tell me about T1566" --technique T1566
```
Expected: Returns Phishing technique with description, mitigations, detection, platforms, tactics.

```powershell
# Sub-technique lookup
.\innoigniter.exe investigate "lsass memory" --technique T1003.001
```
Expected: Returns LSASS Memory sub-technique with Credential Guard mitigations.

```powershell
# IOC enrichment (known Mimikatz hash)
.\innoigniter.exe investigate "check hash" --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```
Expected: IOC enrich returns `builtin_match: true`, `reputation: malicious`, `confidence: 0.95`, tags `["mimikatz", "credential-access"]`.

```powershell
# CVE lookup (requires internet)
.\innoigniter.exe investigate "check cve" --cve-id CVE-2024-3094
```
Expected: CVE data with severity, CVSS score, description, affected products. Falls back gracefully if NVD is unreachable.

```powershell
# Malware family lookup
# Currently returns MITRE mappings for the search term
.\innoigniter.exe investigate "mimikatz" --playbook mitre-lookup --technique T1003.001
```

```powershell
# Unit tests
go test ./internal/knowledge/... -v -count=1
```
Expected: MITRE DB loading, search, sub-technique lookup, IOC enrichment with cache, CVE error handling all pass.

---

## Phase 4 — Detection Agent

```powershell
# YARA scan on a file (use a test file)
echo "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" > eicar.txt
.\innoigniter.exe investigate "scan file" --playbook file-analysis -f .\eicar.txt
```
Expected: YARA matches EICAR test pattern, PE analysis reports "not a PE file", hash lookup runs.

```powershell
# PE analysis on a real PE file
.\innoigniter.exe investigate "analyze pe" --playbook file-analysis -f C:\Windows\System32\notepad.exe
```
Expected: PE metadata (sections, imports, timestamps), YARA scan, hash reputation.

```powershell
# VT lookup (requires VT API key via INNO_VT_API_KEY env var)
$env:INNO_VT_API_KEY = "your-key"
.\innoigniter.exe investigate "check hash vt" --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
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

## Phase 5 — Host Agent (MVP)

```powershell
# Full end-to-end: file analysis with automatic playbook selection
.\innoigniter.exe investigate "check this file" -f C:\Windows\System32\notepad.exe
```
Expected: Intent classifier picks file-analysis, all agents execute, consolidated report with confidence score.

```powershell
# Full end-to-end: hash lookup
.\innoigniter.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```
Expected: Intent classifier extracts hash from query, runs hash-lookup playbook.

```powershell
# Investigation history and status
.\innoigniter.exe serve  # in one terminal
# In another:
# Query the investigation log in .innoigniter/logs/
```

---

## Phase 6 — SIEM engine

```powershell
# Start SIEM engine with config (watches logs\ dir, syslog on :9514)
.\innoigniter.exe serve --config config.json
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
.\innoigniter.exe investigate "block 10.0.0.5" --playbook block-ip --ip 10.0.0.5
```
Expected: Response agent records firewall rule, returns action_id + rollback command.
Note: Requires admin/root privileges on most systems.

```powershell
# Rollback an action by ID
.\innoigniter.exe investigate "rollback previous action" --playbook rollback-action --action-id <action_id>
```

```powershell
# Quarantine a file (moves to restricted quarantine directory)
.\innoigniter.exe investigate "quarantine eicar" --playbook quarantine-file -f .\eicar.txt
```
Expected: File moved to `%TEMP%\innoigniter-quarantine\`, permissions set to read-only.

```powershell
# Kill a process by name
.\innoigniter.exe investigate "kill process" --playbook kill-process --name notepad
```

```powershell
# Restart a service
.\innoigniter.exe investigate "restart service" --playbook restart-service --name BITS
```

```powershell
# List all response actions in database
# (query via SQLite directly)
sqlite3 .innoigniter\innoigniter.db "SELECT id, action_name, target, status, created_at FROM response_actions ORDER BY created_at DESC LIMIT 10"
```

```powershell
# Unit tests
go test ./internal/response/... -v -count=1
```
Expected: 10 tests (block IP with/without target, quarantine missing file, kill process, restart service, rollback, all actions return ID, name, capabilities).

---

## Phase 8 — Plugins

```powershell
# Install a plugin
.\innoigniter.exe plugin install inno-splunk
```

```powershell
# List installed plugins
.\innoigniter.exe plugin list
```

---

## Phase 9 — Central server

```powershell
# Start in server mode
.\innoigniter.exe server
```
Expected: gRPC listener, web UI at configured address.

```powershell
# Two edge nodes report to server
# Verify cross-node correlation on server dashboard
```

---

## Phase 10 — Polish

```powershell
# First-run setup
.\innoigniter.exe init
```

```powershell
# Update binary
.\innoigniter.exe update
```

```powershell
# Update intel cache
.\innoigniter.exe update-intel
```

```powershell
# Cross-compile for all platforms
make cross
```

## Quick smoke test (full pipeline)

```powershell
cd dev
go build -o innoigniter.exe .\cmd\innoigniter\
.\innoigniter.exe version
.\innoigniter.exe investigate "check T1566" --technique T1566
.\innoigniter.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
go test ./... -count=1
```

If all three commands pass, the system is healthy.
