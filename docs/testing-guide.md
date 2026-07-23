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

---

## Custom EDR Agent (`trace-agent`)

Trace ships its own endpoint agent — no third-party EDR required. This section covers building, testing, deploying, and verifying every feature of the custom agent.

---

### 1. Build Verification

```bash
cd dev

# Build the agent binary
go build -o trace-agent.exe ./cmd/trace-agent/

# Build the Trace server (needed for EDR management)
go build -o trace.exe ./cmd/trace/

# Quick smoke test: agent --help should show all flags
trace-agent.exe --help
```

Expected: Output shows flags: `--config`, `--server`, `--api-key`, `--install`, `--uninstall`, `--service`, `--status`, `--version`.

```bash
# Vet the entire agent package
go vet ./internal/edr_agent/...
go vet ./cmd/trace-agent/...
```

Expected: Clean — no vet errors.

---

### 2. Unit Tests — All Packages

```bash
cd dev
go test ./internal/edr_agent/... -short -count=1
```

Expected: All packages pass.

#### Package: `edr_agent` (config + lifecycle)

| Test | What it verifies |
|------|------------------|
| ConfigLoad | Reads config file, applies defaults for missing fields |
| ConfigSave | Writes config file, validates JSON round-trip |
| ConfigDefaults | Server URL, API key, poll intervals, queue limits all have correct defaults |
| ConfigValidate | Rejects empty server URL, validates port ranges |

#### Package: `edr_agent/monitor`

##### YARA Matcher (28 test cases + 2 benchmarks)

```bash
go test ./internal/edr_agent/monitor -run TestYara -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestYaraMatcherEICAR | Scan string "X5O!P%@AP[4\PZX54..." | Match rule `EICAR`, confident ≥ 0.99 |
| TestYaraMatcherPowerShell | PowerShell invocation string | Match `Suspicious_PowerShell` |
| TestYaraMatcherCMD | cmd.exe with suspicious flags | Match `Suspicious_CMD` |
| TestYaraMatcherBase64 | Long base64-encoded string | Match `Base64_Encoded_Strings` |
| TestYaraMatcherEntropy | High-entropy string (random) | Match `Suspicious_Entropy` |
| TestYaraMatcherNoMatch | Benign text ("hello world") | No matches |
| TestYaraMatcherEmptyInput | Empty byte slice | No matches, no panic |
| TestYaraMatcherNilInput | nil input | No matches, no panic |
| TestYaraMatcherMimikatz | Mimikatz signature strings | Match `Mimikatz_Strings` |
| TestYaraMatcherCobaltStrike | CobaltStrike beacon config | Match `CobaltStrike_Beacon` |
| TestYaraMatcherPackedPE | PE section names "UPX0", "UPX1" | Match `Packed_PE_Binary` |
| TestYaraMatcherProcessInjection | API names "CreateRemoteThread" | Match `Process_Injection_API` |
| TestYaraMatcherKeylogger | Keylogger API names | Match `Keylogger_Indicators` |
| TestYaraMatcherXOREncoded | XOR-encoded payload pattern | Match `XOR_Encoded_Payload` |
| TestYaraMatcherMultipleData | Multiple strings, some match, some don't | Only matching rules fire |
| TestYaraMatcherRuleName | Verify returned RuleName field | Correct rule name per match |
| TestYaraMatcherConfidence | Verify confidence is ≥ 0.8 for strong matches | Confidence in expected range |
| TestYaraMatcherLargeInput | 1MB random data | No OOM, no false positives |
| TestYaraMatcherUnicode | Unicode PowerShell invocation | Match (Unicode-aware matching) |
| TestYaraMatcherExternalYar | Load external .yar file from `testdata/rules/` | Loads and matches external rules |
| TestYaraMatcherExternalDir | Point YARA at `testdata/rules/` directory | Loads all .yar files in directory |
| TestYaraMatcherCacheHit | Same hash scanned twice | Second scan uses cache, returns immediately |
| TestYaraMatcherCacheEviction | >1000 unique hashes | Oldest entries evicted, LRU ≤ 1000 |
| TestYaraMatcherConcurrency | 10 goroutines scanning simultaneously | No race conditions, all results correct |
| TestYaraMatcherCustomRuleDir | Set `--yara-dir` to custom path | Loads rules from custom path |
| TestYaraMatcherInvalidRuleFile | .yar file with syntax error | Skips bad file, logs warning, continues |
| TestYaraMatcherMixedSources | Built-in + custom dir + file | Merges all rule sources |

##### XOR Cipher Detector

```bash
go test ./internal/edr_agent/monitor -run TestXor -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestXorSingleByteDetect | XOR with single-byte key 0xAB on 64 bytes | Detects key 0xAB, confidence ≥ 0.90 |
| TestXorSingleByteAllKeys | Tests all 256 single-byte keys | Each key detected correctly |
| TestXorSingleByteShortInput | 8-byte input (below minimum) | Returns no key, not confident |
| TestXorSingleByteLongInput | 4096-byte XOR'd data | Detects key, high confidence |
| TestXorSingleBytePlaintext | Plain ASCII text (no XOR) | No key detected, low confidence |
| TestXorSingleByteEmpty | Empty input | Returns empty, no error |
| TestXorMultiByteDetect | 2-byte XOR key on 128 bytes | Detects key length 2, recovers key bytes |
| TestXorMultiByteLongKey | 16-byte XOR key | Detects key length, recovers all key bytes |
| TestXorMultiByteShortInput | 12-byte input (below minimum) | Returns no key |
| TestXorMultiBytePlaintext | Plain text scanned | No key detected |
| TestXorADDDetect | ADD cipher with key 0x42 on 128 bytes | Detects key 0x42, confidence ≥ 0.90 |
| TestXorADDAllKeys | Tests all 256 ADD keys | Each detected correctly |
| TestXorADDPlaintext | Plain text ADD scan | No key detected |
| TestXorSUBDetect | SUB cipher with key 0x66 on 128 bytes | Detects key 0x66, confidence ≥ 0.90 |
| TestXorSUBAllKeys | Tests all 256 SUB keys | Each detected correctly |
| TestXorROLDetect | ROL cipher with shift 7 on 128 bytes | Detects shift 7 |
| TestXorROLAllShifts | Tests shifts 1–7 | Each detected correctly |
| TestXorROLPlaintext | Plain text ROL scan | No shift detected |
| TestXorEmptyInputs | Empty for all cipher types | All return empty, no error |
| TestXorMultiByteCipherOverlap | 3-byte key with period-3 repeat | Detects period correctly |

##### PE Parser

```bash
go test ./internal/edr_agent/monitor -run TestPe -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestPeParseIAT32 | Parse import table of a 32-bit PE | Returns DLL names, function names, ordinals |
| TestPeParseIAT64 | Parse import table of a 64-bit PE | Returns 64-bit IAT entries |
| TestPeParseEmptyImport | PE with no imports | Returns empty import list, not an error |
| TestPeParseSections | PE with .text, .data, .rdata, .rsrc | Returns section names, sizes, characteristics |
| TestPeParseEmptySections | PE with no sections | Handles gracefully |
| TestPeParsePackerUPX | PE with UPX-packed sections | Returns packer type "UPX" |
| TestPeParsePackerThemida | PE with Themida protection | Returns packer type "Themida" |
| TestPeParsePackerMPRESS | PE with MPRESS compression | Returns packer type "MPRESS" |
| TestPeParsePackerEnigma | PE with Enigma protector | Returns packer type "Enigma" |
| TestPeParsePackerUnknown | PE with no known packer | Returns packer type "none" |
| TestPeParseResourceDir | PE with resource directory | Returns resource entries |
| TestPeParseResourceEmpty | PE with no resources | Returns empty resource list |
| TestPeParseInvalidData | Random bytes (not a PE) | Returns error "not a PE file" |
| TestPeParseNilData | nil input | Returns error, no panic |
| TestPeParseShortHeader | <64 bytes (incomplete DOS header) | Returns error |
| TestPeParseCorrupted | DOS header present but corrupt PE signature | Returns error |

##### Process Ancestry Tree

```bash
go test ./internal/edr_agent/monitor -run TestTree -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestTreeAddAndGet | Add single process, retrieve by PID | Returns process with correct parent, command, time |
| TestTreeParentChain | Add parent → child → grandchild | Chain resolves grandchild → child → parent |
| TestTreeAncestorDepth | 5-deep chain, query depth | Returns correct depth |
| TestTreeLRUEviction | Add 100,001 processes (cap is 100,000) | Oldest entry evicted, count ≤ 100,000 |
| TestTreeGetMissingPID | Query PID that was never added | Returns nil, not found |
| TestTreeWALPersistence | Save tree → crash → reload | Tree state preserved across crash |
| TestTreeWALAppendOnly | Sequential WAL entries | Append does not rewrite full state |
| TestTreeReplayLog | Write WAL entries → replay | Exact same tree restored |
| TestTreeEmptyWAL | No WAL file exists | Empty tree, no error |
| TestTreeConcurrentAdd | 50 goroutines adding PIDs simultaneously | No data races, all PIDs added |

##### Event Dedup

```bash
go test ./internal/edr_agent/monitor -run TestDedup -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestDedupInMemory | Same event seen twice in same session | Second call returns true (duplicate) |
| TestDedupUnique | Different events | Returns false (not a duplicate) |
| TestDedupSQLite | Same event across session restart | Returns true (persisted dedup) |
| TestDedupEmptyEvent | Empty event data | Hashes to a value, no crash |
| TestDedupBatchFlush | 100 events → flush every 50 | Batch written to SQLite in 2 flushes |
| TestDedupLargePayload | 1MB event data | Hashes correctly, no truncation |
| TestDedupConcurrent | 20 goroutines checking same event | Single goroutine wins, no duplicates |
| TestDedupTTL | Event older than TTL | Not considered duplicate |
| TestDedupCrossRestart | SQLite file open/close → reopen | Dedup set persists correctly |

##### Entropy Calculator

```bash
go test ./internal/edr_agent/monitor -run TestEntropy -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestEntropyLow | Uniform byte (0x41, 0x41, ...) → 0.0 | Entropy = 0.0 |
| TestEntropyMax | All bytes different | Approaches 8.0 (max) |
| TestEntropyHalf | 2-value repeating pattern | Entropy ≈ 1.0 |
| TestEntropyEnglish | English text sample | Entropy ≈ 4.0–5.5 |
| TestEntropyHighRandom | High-entropy random bytes | Entropy > 7.5 |
| TestEntropyEmpty | Empty input | Returns 0.0, no error |
| TestEntropyBaselineLoad | Load baseline config from file | Returns pre-computed thresholds |
| TestEntropyBaselineDefault | No config file | Returns sensible defaults |

##### Flood Detector

```bash
go test ./internal/edr_agent/monitor -run TestFlood -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestFloodBelowThreshold | 10 events in 60s (threshold=20) | Not flooding |
| TestFloodAboveThreshold | 30 events in 60s (threshold=20) | Flooding detected |
| TestFloodAdaptiveBaseline | 60s warmup phase | Baseline computed after warmup |
| TestFloodReset | Flood status resets after cooldown | Status returns to normal |
| TestFloodMultipleEventTypes | Process and file events tracked separately | Different thresholds per type |
| TestFloodConfigReload | Update threshold via JSON config + SIGHUP | New threshold applies without restart |
| TestFloodMinMaxThreshold | Min below 20, max above 5000 | Clamped to [20, 5000] |
| TestFloodEmptyHistory | No events yet | Not flooding, no error |

#### Package: `edr_agent/response` (action executor)

```bash
go test ./internal/edr_agent/response -v -count=1
```

| Test | Scenario | Expected |
|------|----------|----------|
| TestKillProcess | Kill process by PID | Process terminated, action recorded |
| TestKillProcessByName | Kill process by name | All matching PIDs killed |
| TestKillProcessMissing | PID does not exist | Returns error, action recorded as failed |
| TestQuarantineFile | Move file to quarantine dir | File moved, permissions set to 0444 |
| TestQuarantineFileMissing | File does not exist | Returns error, no crash |
| TestBlockIPTables | Block IP via iptables | Rule added, rollback command generated |
| TestBlockIPNetsh | Block IP via netsh (Windows) | Rule added, rollback command generated |
| TestBlockIPPF | Block IP via pfctl (macOS) | Rule added, rollback command generated |
| TestRunScript | Execute script from URL | Script downloaded, executed, output captured |
| TestRunScriptTimeout | Script exceeds timeout | Killed after timeout, partial output returned |
| TestIsolateHost | Enable host-level firewall, deny all inbound | All inbound blocked, rollback command saved |
| TestReleaseHost | Disable isolation (restore inbound) | Original firewall rules restored |
| TestCollectForensics | Collect system information | Returns process list, network connections, disk usage |
| TestSystemSnapshot | Full snapshot of system state | Returns processes, network, files, registry keys |
| TestUnknownAction | Action name not recognized | Returns error, no crash |
| TestActionTimeout | Action exceeds max duration | Action cancelled, timeout error returned |
| TestActionChaining | kill_process → quarantine_file → block_ip | All three execute in sequence, chained correctly |
| TestActionRollbackVerification | Execute action → verify rollback restores state | Rollback returns system to pre-action state |
| TestMultipleTargets | block_ip with 5 IPs | All IPs blocked individually |

---

### 3. Performance Benchmarks

```bash
cd dev

# YARA matcher throughput
go test ./internal/edr_agent/monitor -bench=BenchmarkYaraMatcher -benchmem -count=1 -benchtime=1000x

# XOR detector throughput
go test ./internal/edr_agent/monitor -bench=BenchmarkXorDetect -benchmem -count=1

# PE parser throughput
go test ./internal/edr_agent/monitor -bench=BenchmarkPeParse -benchmem -count=1

# Event dedup throughput
go test ./internal/edr_agent/monitor -bench=BenchmarkDedup -benchmem -count=1

# Entropy calculation throughput
go test ./internal/edr_agent/monitor -bench=BenchmarkEntropy -benchmem -count=1

# Flood detector throughput
go test ./internal/edr_agent/monitor -bench=BenchmarkFlood -benchmem -count=1
```

| Benchmark | Ops/sec | Allocs/op | Description |
|-----------|---------|-----------|-------------|
| YaraMatcher (5 samples, 17 rules) | ~1,900 | 2 | Per-sample throughput across all rules |
| XorDetectSingleByte (256 keys) | ~85,000 | 15 | Single-byte key brute-force |
| XorDetectMultiByte (16 keys) | ~12,000 | 42 | Multi-byte with Kasiski + Hamming |
| PeParseIAT (32-bit) | ~24,000 | 8 | Import address table walk |
| PeParseIAT (64-bit) | ~22,000 | 8 | 64-bit IAT walk |
| PeParsePacker | ~250,000 | 3 | Packer detection (section name match) |
| DedupInMemory | ~310,000 | 6 | In-memory SHA-256 hash check |
| DedupSQLite | ~1,200 | 28 | SQLite INSERT + SELECT round-trip |
| Entropy (1KB) | ~470,000 | 3 | Shannon entropy over 1024 bytes |
| FloodDetect | ~520,000 | 5 | Threshold check against sliding window |

---

### 4. Integration Tests (httptest server)

These tests spin up a real HTTP server, register the agent, send events, and verify end-to-end behavior.

```bash
cd dev
go test ./cmd/trace-agent/... -tags=integration -count=1 -v
```

| Test | Scenario | What it verifies |
|------|----------|------------------|
| TestAgentRegistration | Agent starts → POST /api/v1/edr/register | Server receives UUID, hostname, platform, version |
| TestAgentRegistrationDuplicate | Same agent registers twice | Server returns 409 Conflict |
| TestAgentHeartbeat | Agent sends POST /api/v1/edr/heartbeat every 30s | Server updates last_seen timestamp |
| TestAgentHeartbeatMissingAuth | Heartbeat without API key | Server returns 401 Unauthorized |
| TestAgentSendsEvents | Agent batches 5 events → POST /api/v1/edr/events | Server stores all 5, returns 200 |
| TestAgentEventBatchSize | Agent sends 100 events in one batch | All 100 stored correctly |
| TestAgentEventOverflow | Send 2000 events in rapid succession | Queue flushes in batches of 50, none lost |
| TestAgentRecoversFromServerDown | Server returns 503, agent waits, retries | After server 200, agent resumes normal ops |
| TestAgentServerDownMultipleFailures | Server returns 503 × 10 | Circuit breaker opens at 5, rechecks after 60s |
| TestAgentCircuitBreakerHalfOpen | Circuit open → timer fires → probe | Half-open state, if probe succeeds → closed |
| TestAgentDiskQueueFull | Server offline → agent writes 2000 events to disk | Events persisted to SQLite, replayed on reconnect |
| TestAgentDiskQueueEviction | >64MB of queued events | Oldest events evicted, queue stays ≤64MB |
| TestAgentConfigPersistence | Start with --config, modify config, restart | Config changes survive restart |
| TestAgentHMACSigning | Agent signs outgoing request with HMAC | Server verifies HMAC, rejects tampered payload |
| TestAgentmTLS | Agent connects with client certificate | TLS handshake succeeds, cert validated |
| TestAgentServerResponseActions | Server queues action → agent polls → executes | Agent polls GET /api/v1/edr/actions, executes, reports result |
| TestAgentAutoUpdate | Server returns new binary → agent downloads | SHA256 verified, binary swapped atomically, backup created |

---

### 5. Real Deployment Tests

These scripts run against a live agent to verify production behavior under load, stress, and fault conditions.

```bash
# Prerequisites: deploy and run both server and agent
go build -o trace-agent.exe ./cmd/trace-agent/
trace.exe server --http-addr :8080
# In another terminal:
trace-agent.exe --server http://localhost:8080 --api-key test-key --verbose
```

#### Soak Test (long-running stability)

```bash
# Syntax: bash deploy/soak-test.sh <duration-seconds> <server-url> <api-key>

# Run for 1 hour
bash deploy/soak-test.sh 3600 http://localhost:8080 test-key

# Run for 24 hours
bash deploy/soak-test.sh 86400 http://localhost:8080 test-key
```

What it does:
- Sends random process/file/network events every 5–15s
- Simulates agent restarts every 30 minutes
- Verifies events appear on server after each restart
- Reports: total events sent, events received, uptime %, restarts tolerated

Expected: 100% event delivery rate, no memory leaks, agent recovers after each restart.

#### Volume Stress Test

```bash
bash deploy/stress-test.sh
```

What it does:
- Generates 10,000 events in 60 seconds (flood simulation)
- Tests queue back-pressure and circuit breaker
- Measures: peak throughput, p50/p95/p99 latency, queue depth

Expected: No data loss at peak, circuit breaker opens within bounds, queue recovers.

#### Malware Detection Test

```bash
# Requires: YARA enabled, EICAR test file
bash deploy/malware-test.sh
```

What it does:
- Creates EICAR test file on monitored directory
- Generates Mimikatz-like process events
- Creates high-entropy temp files
- Triggers XOR-encoded payload pattern
- Verifies each detection arrives at server

Expected: All 5 detections reach server within 30s. Each has correct rule name and confidence ≥ 0.8.

#### Crash Recovery Test

```bash
bash deploy/crash-test.sh
```

What it does:
- Starts agent, sends 100 events
- Kills agent with SIGKILL (or Taskkill /F on Windows)
- Restarts agent, checks process tree WAL replay
- Verifies dedup cache survives
- Counts events delivered after restart

Expected: Process tree intact, dedup set preserved, remaining events sent after restart.

---

### 6. CLI Verification Commands

```bash
cd dev
go build -o trace.exe ./cmd/trace/
go build -o trace-agent.exe ./cmd/trace-agent/
```

#### Build & Status

```bash
# Verify version
trace-agent.exe --version

# Check agent status (before running)
trace-agent.exe --status

# Start agent (foreground, verbose)
trace-agent.exe --server http://localhost:8080 --api-key test-key --verbose

# Start agent as Windows service
trace-agent.exe --install --server http://localhost:8080 --api-key test-key

# Verify service status
trace-agent.exe --status
```

Expected: `--status` shows `running` with PID, uptime, connected server URL.

#### EDR Management (from Trace server)

```bash
# List all agents
trace edr list

# View agent details
trace edr view <agent-id>

# View recent events (last 50)
trace edr events <agent-id>

# View events filtered by type
trace edr events <agent-id> --type process
trace edr events <agent-id> --type file
trace edr events <agent-id> --type network

# View events within time range
trace edr events <agent-id> --since 1h
trace edr events <agent-id> --since 2026-07-22T00:00:00Z --until 2026-07-22T23:59:59Z

# View high-severity events only
trace edr events <agent-id> --min-severity 3
```

#### Response Actions

```bash
# Kill a process by PID
trace edr dispatch <agent-id> kill_process --pid 1234

# Kill all processes by name
trace edr dispatch <agent-id> kill_process --name notepad.exe

# Quarantine a file
trace edr dispatch <agent-id> quarantine_file --path C:\malware.exe

# Block an IP
trace edr dispatch <agent-id> block_ip --ip 203.0.113.42

# Block multiple IPs
trace edr dispatch <agent-id> block_ip --ip 203.0.113.42 --ip 10.0.0.5

# Run a script from URL
trace edr dispatch <agent-id> run_script --script "curl -s https://scripts.example.com/remediate.ps1 | powershell -"

# Run a script with timeout
trace edr dispatch <agent-id> run_script --script "ping -n 30 127.0.0.1" --timeout 10

# Isolate a host (block all inbound)
trace edr dispatch <agent-id> isolate_host

# Release a host from isolation
trace edr dispatch <agent-id> release_host

# Collect forensics snapshot
trace edr dispatch <agent-id> collect_forensics

# Full system snapshot
trace edr dispatch <agent-id> system_snapshot
```

#### False Positive Management

```bash
# List all dismissals
trace edr dismiss --list

# Dismiss an alert (trains FP learning model)
trace edr dismiss <alert-id>

# Dismiss with note
trace edr dismiss <alert-id> --reason "Legitimate admin activity"

# View FP learning stats
trace edr dismiss --stats

# Remove an agent
trace edr revoke <agent-id>
```

Expected: After 10 dismissals of the same event type, that type auto-throttles (fewer alerts).

#### Action History

```bash
# View action status
trace edr view <agent-id>
# Look for "last_action" and "action_status" fields

# List all dispatched actions server-side
sqlite3 ~/.trace/trace.db "SELECT id, action, target, status, created_at FROM edr_actions ORDER BY created_at DESC LIMIT 20"
```

---

### 7. Event Pipeline Verification

Test the full event pipeline end-to-end:

```bash
# Terminal 1 — Start Trace server
trace.exe server --http-addr :8080

# Terminal 2 — Start agent in verbose mode
trace-agent.exe --server http://localhost:8080 --api-key test-key --verbose --poll-interval 5s

# Terminal 3 — Generate events and verify
```

#### Process Events

```bash
# Start notepad → agent should detect via process monitor
notepad.exe

# Check server events:
trace edr events <agent-id> --type process --min-severity 1
```

Expected: Process creation event with PID, parent PID, command line, user, timestamp.

#### File Events

```bash
# Create, modify, delete files in monitored directory
echo "test" > C:\temp\test.txt
del C:\temp\test.txt
```

Expected: `file_create`, `file_modify`, `file_delete` events with full path, size, hash.

#### Network Events

```bash
# Make a network connection
curl https://example.com
```

Expected: `network_connect` event with source IP:port, dest IP:port, protocol.

#### Memory Scan Events

```bash
# Agent scans running processes periodically
# Check for YARA matches
trace edr events <agent-id> --type memory --min-severity 3
```

Expected: Memory scan events with YARA rule name, PID, process name, matched bytes.

#### USB Events

```bash
# Plug in a USB drive
# Agent should detect within poll interval (default 10s)
```

Expected: `usb_insert` event with vendor ID, product ID, serial, mount point.

#### DNS Query Events (Windows only)

```bash
# Make a DNS query
nslookup evil.com
```

Expected: `dns_query` event with query name, query type, response IPs.

#### Code Integrity Events (Windows only)

```bash
# Run an unsigned binary (if CI policy is strict)
```

Expected: `code_integrity` event with file path, hash, signature status.

---

### 8. Advanced: Server-Side EDR Endpoints

```bash
# List registered agents (REST API)
curl -H "Authorization: Bearer $(trace genkey)" http://localhost:8080/api/v1/edr/agents

# Get agent details
curl -H "Authorization: Bearer $(trace genkey)" http://localhost:8080/api/v1/edr/agents/<agent-id>

# List events for an agent (paginated)
curl -H "Authorization: Bearer $(trace genkey)" "http://localhost:8080/api/v1/edr/events?agent_id=<agent-id>&limit=50&offset=0"

# Filter events by severity
curl -H "Authorization: Bearer $(trace genkey)" "http://localhost:8080/api/v1/edr/events?agent_id=<agent-id>&min_severity=3"

# List pending response actions
curl -H "Authorization: Bearer $(trace genkey)" http://localhost:8080/api/v1/edr/actions?agent_id=<agent-id>

# Dispatch a response action (same as CLI)
curl -X POST -H "Authorization: Bearer $(trace genkey)" \
  -H "Content-Type: application/json" \
	-d '{"action":"isolate_host","target":""}' \
  http://localhost:8080/api/v1/edr/dispatch/<agent-id>

# List dismissals (FP learning data)
curl -H "Authorization: Bearer $(trace genkey)" http://localhost:8080/api/v1/edr/dismissals
```

---

### 9. Database Inspection

```bash
# EDR agents table
sqlite3 ~/.trace/trace.db "SELECT id, hostname, platform, status, version, last_seen, created_at FROM edr_agents ORDER BY last_seen DESC"

# EDR events table
sqlite3 ~/.trace/trace.db "SELECT id, agent_id, event_type, severity, summary, created_at FROM edr_events ORDER BY created_at DESC LIMIT 20"

# EDR response actions table
sqlite3 ~/.trace/trace.db "SELECT id, agent_id, action, target, status, result, created_at FROM edr_actions ORDER BY created_at DESC LIMIT 20"

# FP counter table
sqlite3 ~/.trace/trace.db "SELECT event_type, dismiss_count, auto_throttled FROM edr_fp_counters ORDER BY dismiss_count DESC"
```

---

### 10. Full Pipeline Smoke Test

```powershell
cd dev
go build -o trace.exe .\cmd\trace\
go build -o trace-agent.exe .\cmd\trace-agent\

# Start server (in a terminal)
.\trace.exe server --http-addr :8080

# In another terminal — start agent
.\trace-agent.exe --server http://localhost:8080 --api-key test-key --verbose

# In another terminal — run tests
$env:TRACE_API_KEY = "f19efa85-834f-4978-901d-"

# List active agents
.\trace.exe edr list

# Get agent ID (first active agent)
$lines = .\trace.exe edr list
foreach ($line in $lines) { if ($line -match '^  [0-9a-f-]{36}') { $AID = $matches[0].Trim(); break } }

# View agent detail (shows CPU name, memory in GB, IP)
.\trace.exe edr view $AID

# Generate file event
mkdir C:\temp -Force
echo "hello" > C:\temp\test.txt
Start-Sleep 8

# Check file events
.\trace.exe edr events $AID --type file --limit 5

# Generate EICAR test (triggers YARA scan)
"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" | Out-File -FilePath C:\temp\eicar.txt -Encoding ascii
Start-Sleep 8

# Check for YARA detection (shows rule name + event ID)
.\trace.exe edr events $AID --type alert --limit 5

# Dismiss a false positive
.\trace.exe edr dismiss <event-id-from-above> --reason "Test FP"

# Dispatch a response action (run agent as admin for firewall changes)
.\trace.exe edr dispatch $AID block_ip --ip 203.0.113.42

# Verify firewall rule
netsh advfirewall firewall show rule name=trace-block-203-0-113-42

# Run all unit tests
go test .\internal\edr_agent\... -short -count=1
```

Expected: Full pipeline — server starts, agent registers, events flow with YARA rule names visible, dismissals work, actions dispatch and execute, tests pass.

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
