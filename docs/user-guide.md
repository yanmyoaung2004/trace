# InnoIgniterAI — Analyst User Guide

> End-to-end walkthrough for security analysts using the platform.

---

## Table of Contents

1. [Installation & Setup](#1-installation--setup)
2. [First Run](#2-first-run)
3. [Quick Investigation](#3-quick-investigation)
4. [Understanding Reports](#4-understanding-reports)
5. [Playbooks Deep Dive](#5-playbooks-deep-dive)
6. [SIEM Monitoring](#6-siem-monitoring)
7. [Intel Feeds & Enrichment](#7-intel-feeds--enrichment)
8. [Response Actions](#8-response-actions)
9. [Central Server & Team Use](#9-central-server--team-use)
10. [Troubleshooting](#10-troubleshooting)
11. [Real-World Scenario Walkthrough](#11-real-world-scenario-walkthrough)

---

## 1. Installation & Setup

### Windows

```powershell
# Build from source
cd dev
go build -o innoigniter.exe .\cmd\innoigniter\

# Or download a release binary
# (once releases are published to GitHub)
```

### Linux / macOS

```bash
cd dev
go build -o innoigniter ./cmd/innoigniter
```

### Docker

```bash
cd dev
docker compose up server
# Dashboard at http://localhost:8080
```

---

## 2. First Run

### Quick start (no config needed)

```powershell
# Check version
.\innoigniter.exe version

# Run an investigation immediately (uses defaults)
.\innoigniter.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```

### Interactive setup

```powershell
.\innoigniter.exe init
```

The wizard prompts for:
- **VirusTotal API key** — hash/URL/IP lookups (free tier: 500/day)
- **LLM provider** — for intent classification (optional)
- **Web search key** — threat intel web searches (optional)
- **AbuseIPDB key** — free IP reputation (recommended)
- **AlienVault OTX key** — free threat intel (recommended)
- **SIEM monitoring** — enable log watching
- **Telemetry** — opt-in usage stats

All prompts are skippable. Without API keys, local analysis still works.

### Environment variables

```powershell
$env:INNO_VT_API_KEY = "your-vt-key"
$env:INNO_ABUSEIPDB_KEY = "your-abuseipdb-key"
$env:INNO_OTX_API_KEY = "your-otx-key"
```

---

## 3. Quick Investigation

### By natural language

```powershell
innoigniter investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```

The intent classifier recognizes "check hash" and runs the `hash-lookup` playbook.

### By explicit playbook

```powershell
innoigniter investigate --playbook file-analysis --param path=C:\Windows\System32\notepad.exe
innoigniter investigate --playbook domain-reputation --param domain=evil.com
innoigniter investigate --playbook ip-enrich --param ip=185.220.101.24
```

### Investigation history

```powershell
innoigniter history
innoigniter status <investigation-id>
innoigniter report <investigation-id>
```

---

## 4. Understanding Reports

Every investigation produces a markdown report with:

```
# Investigation Report

**Intent:** check hash 275a021b...
**ID:** `abc123...`
**Confidence:** 90%

## Summary
[HIGH] detection.hash_lookup: malicious

## Findings
- malicious_indicator [detection.hash_lookup]: malicious

## Indicators
- 275a021b... (detection.hash_lookup)

## Agent Results
### detection.hash_lookup
- **Reputation:** malicious
- **Source:** builtin
### knowledge.ioc_enrich
- **Intel:** {builtin_match: true, reputation: malicious}
- **MITRE mappings:** Mimikatz → T1003
```

### Confidence scoring

| Score | Meaning |
|---|---|
| 90-100% | Highly likely malicious (multiple sources agree) |
| 70-89% | Likely malicious (one strong source) |
| 40-69% | Suspicious (some indicators present) |
| <40% | Inconclusive (no strong signals) |

---

## 5. Playbooks Deep Dive

### Available playbooks

| Playbook | What it does | Best for |
|---|---|---|
| `hash-lookup` | Check hash vs cache + YARA + VT + intel | File hash triage |
| `file-analysis` | Hash + YARA + PE metadata + intel | Malware sample analysis |
| `ip-reputation` | VT lookup + IOC enrichment | IP address triage |
| `domain-reputation` | IOC enrich + VT + web search | Domain/URL triage |
| `ip-enrich` | AbuseIPDB + OTX + VT + IOC | Deep IP enrichment |
| `email-analysis` | Sender IP → hash → domain → web search | Phishing email analysis |
| `network-scan` | Multi-indicator network analysis | Network threat hunting |
| `log-analysis` | YARA + hash + IOC + MITRE + CVE | Log event analysis |
| `windows-event-analysis` | IOC enrich + MITRE + web search + hash | Windows event triage |
| `registry-check` | Registry key + MITRE + web search + hash | Persistence detection |
| `mitre-lookup` | MITRE ATT&CK technique details | Threat intelligence |
| `cve-lookup` | CVE severity, CVSS, affected products | Vulnerability response |
| `block-ip` | Firewall rule via netsh/iptables | Immediate containment |
| `quarantine-file` | Move to restricted directory | File containment |
| `kill-process` | Terminate by name or PID | Process containment |
| `restart-service` | Restart system service | Service recovery |
| `rollback-action` | Undo previous response action | Mistake recovery |
| `slack-notify` | Send alert to Slack webhook | Team notification |
| `discord-notify` | Send alert to Discord webhook | Team notification |

### How playbooks work

Playbooks are YAML files with sequential steps:

```yaml
name: hash-lookup
triggers:
  - hash
  - check hash
steps:
  - agent: detection
    action: hash_lookup
    params:
      hash: ${input.hash}
  - agent: detection
    action: yara_scan
    params:
      path: ${input.path}
    optional: true
  - agent: detection
    action: vt_lookup
    params:
      hash: ${input.hash}
    optional: true
    timeout: 30s
```

Key features:
- **`optional: true`** — step failure doesn't block the playbook
- **`timeout`** — per-step deadline (e.g. `30s`, `5m`)
- **`if`** — conditional execution: `'${result.detection.yara_scan.count} != "0"'`
- **`wait: analyst_approval`** — human-in-the-loop gate

### Variable interpolation

| Pattern | Resolves to |
|---|---|
| `${input.hash}` | Investigation input parameter |
| `${input.path}` | File path from input |
| `${result.agent.action.key}` | Output from a previous step |
| `${outputs.agent.action.key}` | Same as result |

---

## 6. SIEM Monitoring

### Starting the SIEM engine

```powershell
# Watch directories + listen on syslog
innoigniter serve --siem --log-dir C:\Logs --syslog-addr :514
```

### Built-in detection rules (16 total)

| Rule | Event | Severity |
|---|---|---|
| `MULTIPLE_FAILED_LOGINS` | 5 auth failures in 60s | 4 |
| `FAILED_LOGIN_BRUTE` | 20 auth failures in 60s | 5 |
| `HTTP_5XX_ERROR` | Server error | 3 |
| `HTTP_4XX_BURST` | 10 client errors in 60s | 2 |
| `SUSPICIOUS_PROCESS` | Suspicious process | 4 |
| `WINDOWS_EVENT_4625_BURST` | 5 failed logons | 4 |
| `WIN_POWERSHELL_4104` | PowerShell script block | 3 |
| `WIN_SCHEDULED_TASK_4698` | Scheduled task created | 4 |
| `WIN_SERVICE_INSTALL_7045` | New service installed | 4 |
| `WIN_DEFENDER_1116` | Defender detected malware | 5 |
| `WIN_PROCESS_4688_CREATION` | Process created | 2 |
| `WIN_REGISTRY_PERSISTENCE` | Registry changed | 3 |
| `WIN_RDP_LOGIN_4625` | RDP failed login | 3 |
| `WIN_ACCOUNT_LOCKOUT_4740` | Account locked out | 3 |

### SIEM alert → playbook auto-trigger

When a rule fires, it can auto-trigger a playbook:

```
SIEM ALERT: [4] Multiple failed login attempts from same source
  → playbook "ip-reputation" triggered with ip=10.0.0.5
  → investigation completed — report available
```

---

## 7. Intel Feeds & Enrichment

### Built-in IOCs (18 entries)

The platform ships with known malware hashes and indicators:

- **EICAR** — antivirus test file
- **Mimikatz** — credential dumping (T1003)
- **CobaltStrike** — C2 beacon payloads
- **Emotet** — banking trojan downloader
- **Ryuk** — targeted ransomware
- **PlugX** — APT-related RAT
- **AgentTesla** — info-stealer
- **WannaCry** — ransomware worm
- **MITRE techniques** — T1003, T1566, T1059, T1547, T1053
- **CVEs** — Log4Shell, XZ backdoor

### External feeds

| Feed | Free tier | API key | Command |
|---|---|---|---|
| VirusTotal | 500/day | `INNO_VT_API_KEY` | Auto-used in playbooks |
| AbuseIPDB | 1000/day | `INNO_ABUSEIPDB_KEY` | `ip-enrich` playbook |
| AlienVault OTX | Unlimited | `INNO_OTX_API_KEY` | `ip-enrich` playbook |

### Multi-feed enrichment

```powershell
# Enrich an IP with ALL sources
innoigniter investigate --playbook ip-enrich --param ip=185.220.101.24
```

This checks the IP against:
1. AbuseIPDB (confidence score + report count)
2. AlienVault OTX (pulse count)
3. VirusTotal (if API key configured)
4. Local IOC cache (known indicators)

---

## 8. Response Actions

> ⚠ Requires administrator/root privileges.

### Block an IP

```powershell
innoigniter investigate --playbook block-ip --param ip=10.0.0.5
```

On Windows: adds firewall rule via `netsh advfirewall`.
On Linux: adds rule via `iptables`.
On macOS: adds rule via `pfctl`.

### Quarantine a file

```powershell
innoigniter investigate --playbook quarantine-file --param path=C:\Users\admin\malware.exe
```

Moves file to `%TEMP%\innoigniter-quarantine\`.

### Kill a process

```powershell
innoigniter investigate --playbook kill-process --param name=malware.exe
```

### Rollback

```powershell
# List recent action IDs from DB, then:
innoigniter investigate --playbook rollback-action --param action_id=<action-id>
```

### Human-in-the-loop approval

For playbooks with `wait: analyst_approval`:

```powershell
innoigniter approval pending
innoigniter approval approve <investigation-id>
innoigniter approval deny <investigation-id>
```

---

## 9. Central Server & Team Use

### Start the server

```powershell
innoigniter server --http-addr :8080
```

Opens dashboard at `http://localhost:8080`:
- Investigation list with status filter
- Search by IOC, intent, or ID
- Investigation detail with full report
- Cross-node IOC correlations

### Add edge nodes (Windows endpoints)

```powershell
innoigniter serve --server-addr http://server-hostname:8080
```

Edge nodes:
- Register automatically with the server
- Heartbeat every 30 seconds
- Push investigations to server in real-time
- Show up in the dashboard's node list

### Cross-node IOC correlation

When the same IOC (e.g., a malware hash) is seen on 2+ edges:

| Nodes | Confidence | Meaning |
|---|---|---|
| 1 | 0.5 | Single sighting |
| 2 | 0.75 | Possible campaign |
| 3+ | 0.9 | Confirmed campaign |

Dashboard → Correlations tab shows all cross-node IOCs.

---

## 10. Troubleshooting

### Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| `VT API key not configured` | No VirusTotal key | Set `$env:INNO_VT_API_KEY` |
| `path is required` | Missing parameter | Use `--param path=...` |
| `playbook not found` | Typo in name | Run `innoigniter plugin list` to see available playbooks |
| `connection refused` on server sync | Server not running | Start `innoigniter server` first |
| Investigation stuck on `running` | Task worker not started | Start `innoigniter serve` |
| `The requested operation requires elevation` | Admin rights needed | Run PowerShell as Administrator |
| `abuseipdb rate limited` | Free tier exceeded | Wait 1 minute or upgrade API key |
| DB locked errors | Multiple concurrent writes | Reduce concurrent investigations |

### Logs

```powershell
# Investigation audit logs
dir $env:USERPROFILE\.innoigniter\logs\

# View a specific investigation log
type $env:USERPROFILE\.innoigniter\logs\<investigation-id>.jsonl
```

### Reset

```powershell
# Delete database and start fresh
Remove-Item -Recurse $env:USERPROFILE\.innoigniter\
```

---

## 11. Real-World Scenario Walkthrough

### Scenario: Suspicious email with attachment

An analyst receives a report of a suspicious email with an attachment.

**Step 1 — Extract indicators from the email**

```
From: hr@evil-phish.com
Subject: Urgent: Invoice Past Due
Attachment: invoice-2024-07-18.docm
Sender IP: 185.220.101.24
Link: http://evil-phish.com/payload
```

**Step 2 — Investigate the sender domain**

```powershell
innoigniter investigate --playbook domain-reputation --param domain=evil-phish.com
```

**Step 3 — Investigate the sender IP**

```powershell
innoigniter investigate --playbook ip-enrich --param ip=185.220.101.24
```

**Step 4 — Run email analysis**

```powershell
innoigniter investigate --playbook email-analysis `
  --param sender_ip=185.220.101.24 `
  --param sender_domain=evil-phish.com `
  --param subject="Urgent: Invoice Past Due" `
  --param attachment_hash=<hash-of-attachment>
```

**Step 5 — If malicious indicator found, quarantine**

```powershell
innoigniter investigate --playbook quarantine-file --param path=C:\Downloads\invoice-2024-07-18.docm
```

**Step 6 — Notify the team**

```powershell
innoigniter investigate --playbook slack-notify `
  --param webhook_url=https://hooks.slack.com/services/... `
  --param title="Phishing campaign detected" `
  --param message="evil-phish.com | 185.220.101.24 | attachment quarantined"
```

**Step 7 — Check history and report**

```powershell
innoigniter history
innoigniter report <investigation-id>
```

### Scenario: Windows endpoint showing signs of compromise

A Windows server triggers a SIEM alert for multiple failed logins followed by a new service installation.

**Step 1 — SIEM auto-detects and triggers playbook**

```
SIEM ALERT: [4] Multiple failed login attempts from same source
→ playbook "ip-reputation" triggered
→ investigation completed

SIEM ALERT: [4] New service installed (Event 7045)
```

**Step 2 — Investigate the service**

```powershell
innoigniter investigate --playbook windows-event-analysis `
  --param event_id=7045 `
  --param event_description="unknown service installed" `
  --param technique=T1543.003
```

**Step 3 — Check for persistence (registry)**

```powershell
innoigniter investigate --playbook registry-check `
  --param registry_key=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run `
  --param technique=T1547.001
```

**Step 4 — Analyze any dropped files**

```powershell
innoigniter investigate --playbook file-analysis --param path=C:\Windows\Temp\svchost.exe
```

**Step 5 — Kill the malicious process**

```powershell
innoigniter investigate --playbook kill-process --param name=svchost.exe
```

**Step 6 — Block the attacker IP**

```powershell
innoigniter investigate --playbook block-ip --param ip=185.220.101.24
```

**Step 7 — Generate full report**

```powershell
innoigniter report <investigation-id> -o breach-report.md
```

---

> For playbook authoring: see `docs/playbook-authoring.md`
> For plugin development: see `docs/plugin-development.md`
> For CLI reference: see `docs/cli-reference.md`
