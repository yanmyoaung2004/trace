# Landing Page Reference Data

## Product Identity

| Field | Value |
|-------|-------|
| Name | TRACE |
| Tagline | Autonomous AI That Investigates Cyber Threats |
| Version | v0.1.1 |
| Tagline (alt) | One binary. Full SOC. |
| License | MIT |
| Language | Go |

---

## Agents (7 core)

| Agent | Role | Actions |
|-------|------|---------|
| **Dispatch** | Planner / orchestrator | `synthesize_report`, `plan_investigation`, `classify_intent`, `calculate_confidence` |
| **Sift** | Malware analysis | `yara_scan`, `pe_analyze`, `hash_lookup`, `vt_lookup`, `scan_rootkits`, `check_trojans` |
| **Archive** | Threat intelligence | `mitre_lookup`, `cve_lookup`, `malware_lookup`, `ioc_enrich`, `web_search` |
| **Response** | Host response | `block_ip`, `quarantine_file`, `kill_process`, `restart_service`, `rollback` |
| **SCA** | Compliance scanning | `run_policy`, `scan_system`, `list_policies` |
| **Notifier** | Notifications | `slack`, `discord`, `telegram` |
| **Exporter** | Report serving | `serve_reports` |

### Workflow
```
Alert → Dispatch Agent → [Archive, Sift, Response] → Report
```

Dispatch receives input → classifies intent → selects playbook → dispatches tasks to specialists in parallel → collects results → synthesizes final report.

---

## SIEM Engine

### Rules
| Category | Count |
|----------|-------|
| Wazuh-derived rules | 446 |
| Built-in rules | 16 |
| Kubernetes rules | 34 |
| **Total** | **496** |

### Built-in Rule IDs (16)
MULTIPLE_FAILED_LOGINS, FAILED_LOGIN_BRUTE, HTTP_5XX_ERROR, HTTP_4XX_BURST, SUSPICIOUS_PROCESS, HIGH_SEVERITY_ERROR, WINDOWS_EVENT_4625_BURST, BRUTE_FORCE_FALLBACK, WIN_POWERSHELL_4104, WIN_SCHEDULED_TASK_4698, WIN_SERVICE_INSTALL_7045, WIN_DEFENDER_1116, WIN_PROCESS_4688_CREATION, WIN_REGISTRY_PERSISTENCE, WIN_RDP_LOGIN_4625, WIN_ACCOUNT_LOCKOUT_4740

### K8s Rule Categories (8)
Execution, Credential Access, Persistence, Privilege Escalation, Defense Evasion, Discovery, Lateral Movement, Impact

### Decoders (9)
| Name | Purpose |
|------|---------|
| `json` | NDJSON, JSON object per line |
| `apache` | Apache combined/error log formats |
| `syslog` | RFC 3164 syslog format |
| `csv` | CSV log parsing |
| `windows_event` | Custom Windows event text format |
| `evtx` | Windows EVTX XML |
| `k8s_audit` | Kubernetes audit event JSON |
| `wazuh` | Wazuh agent JSON format |
| `auto` | Tries all decoders in sequence |

### Wazuh Decoders
1,567 decoder definitions embedded from Wazuth.
Covers: sshd, sudo, su, pam, auditd, syslog, fim-state, apache, agent-upgrade, agent-restart, wazuh-api, and more.

### Correlation Features
- Time-windowed event correlation
- Per-rule suppression durations
- Auto-playbook triggering from rule actions
- Field operators: `==`, `!=`, `~=` (regex), `>`, `<`, `in` (CIDR)

---

## Sift Agent — Malware Analysis

### YARA Rules (15)
EICAR_Test, Suspicious_PowerShell, Suspicious_CMD, Base64_Encoded_Strings, Suspicious_Entropy, Packed_Binary, Suspicious_Imports, Process_Injection_API, Keylogger_Indicators, Ransomware_Indicators, VM_Escape_Indicators, JavaScript_Obfuscation, Suspicious_URL_Strings, Mimikatz_Strings, CobaltStrike_Beacon

### Rootkit Signatures
- **271** file patterns across 60+ rootkit families (Adore, t0rn, Knark, Lion, SuckIT, Fu, etc.)
- **76** trojan binary signatures (ls, env, echo, chown, chmod, cat, bash, sh, login, passwd, etc.)
- **8** OS behavior checks (hidden processes, kernel modules, LD_PRELOAD, fileless malware, container escape, persistence, etc.)

### Built-in Hash Cache (9)
Mimikatz, EICAR test file, CobaltStrike beacon (×2), Emotet downloader (×2), Ryuk ransomware, PlugX RAT, AgentTesla, WannaCry

---

## Archive Agent — Threat Intelligence

### MITRE ATT&CK
81 techniques with ID, name, description, tactics, platforms, mitigations, detection.

### CVE Lookup
NVD API v2.0 with SQLite caching (24h TTL). Returns CVSS score, severity, vector, description, affected CPEs.

### Built-in Intel (23 IOCs)
- 12 malicious hashes
- 6 malicious IPs
- 3 malicious domains
- Covers: EICAR, Mimikatz, CobaltStrike, Emotet, Ryuk, PlugX, Remcos, AgentTesla, WannaCry, TrickBot, QakBot, NjRAT, DarkComet, Lokibot, FormBook

### Web Search
Firecrawl API for OSINT gathering.

---

## Playbooks (26)

### Analysis
hash-lookup, ip-reputation, ip-enrich, domain-reputation, file-analysis, email-analysis, cve-lookup, mitre-lookup, log-analysis

### Enrichment
full-enrich

### Response
block-ip, quarantine-file, kill-process, restart-service, rollback-action

### Investigation
network-scan, rootkit-scan, registry-check, windows-event-analysis

### EDR
edr-scan, edr-isolate, edr-kill-process

### Compliance
compliance-scan

### Notifications
slack-notify, discord-notify, telegram-notify

---

## Compliance (8 frameworks)

| Framework | ID | Controls |
|-----------|-----|----------|
| PCI DSS v4.0 | `pci_dss_v4.0` | 14 |
| PCI DSS v3.2.1 | `pci_dss_v3.2.1` | 9 |
| HIPAA Security Rule | `hipaa` | 13 |
| GDPR | `gdpr` | 13 |
| NIST SP 800-53 Rev.5 | `nist_sp_800-53` | 12 |
| ISO 27001:2013 | `iso_27001-2013` | 9 |
| SOC 2 | `soc_2` | 5 |
| CIS Critical Security Controls v8 | `cis_csc_v8` | 6 |

### Report Formats
Text, Markdown, HTML, JSON (PDF export for cases)

### Control Statuses
pass, fail, not-covered, not-applicable

---

## EDR Connectors (3 providers)

| Provider | Auth |
|----------|------|
| CrowdStrike | OAuth2 (client_id + secret) |
| SentinelOne | API Token |
| Microsoft Defender for Endpoint | OAuth2 (tenant + client) |

### Operations
get_agent_info, isolate_host, release_host, kill_process, scan_host, run_script

### Safety
- Circuit breaker: 5 failures → open for 60s
- Rate limit: 200ms minimum interval
- Full audit trail

---

## Default Hunts (4)

| Name | Schedule | Playbook | Severity |
|------|----------|----------|----------|
| known-malware-scan | Every 6h | hash-lookup | 5 |
| compliance-audit | Every 24h | compliance-scan | 3 |
| rootkit-sweep | Every 24h | rootkit-scan | 5 |
| k8s-audit | Every 1h | log-analysis | 4 |

---

## CLI Commands (18)

| Command | Alias | Description |
|---------|-------|-------------|
| `init` | — | First-run setup wizard |
| `investigate` | `inv` | Run security investigation |
| `serve` | — | Start daemon (SIEM, scheduler, worker) |
| `server` | — | Central server mode + web dashboard |
| `status` | `st` | View investigation status |
| `history` | `hist` | List recent investigations |
| `report` | — | Generate/view investigation report |
| `case` | — | Manage cases (10 subcommands) |
| `hunt` | — | Manage threat hunts (6 subcommands) |
| `compliance` | — | Compliance scanning (4 subcommands) |
| `approval` | — | HITL approval management |
| `plugin` | — | Plugin management (4 subcommands) |
| `genkey` | — | Generate TLS cert |
| `update` | — | Update binary, intel, or playbooks |
| `version` | — | Print version |

---

## Configuration

### Core
| Field | JSON | Env Override | Default |
|-------|------|-------------|---------|
| DB Path | `db_path` | `TRACE_DB_PATH` | `~/.trace/trace.db` |
| Data Dir | `data_dir` | — | `~/.trace/data` |
| Log Dir | `log_dir` | — | `~/.trace/logs` |
| Playbook Dir | `playbook_dir` | — | `~/.trace/playbooks` |
| Intel Dir | `intel_dir` | — | `~/.trace/intel` |

### API Keys
| Field | JSON | Env Override |
|-------|------|-------------|
| VirusTotal | `vt_api_key` | `TRACE_VT_API_KEY` |
| AbuseIPDB | `abuseipdb_key` | `TRACE_ABUSEIPDB_KEY` |
| AlienVault OTX | `otx_api_key` | `TRACE_OTX_API_KEY` |
| LLM URL | `llm_url` | `TRACE_LLM_URL` |
| LLM API Key | `llm_api_key` | `TRACE_LLM_API_KEY` |
| LLM Model | `llm_model` | `TRACE_LLM_MODEL` |

### Notifications
| Channel | Fields |
|---------|--------|
| Slack | `slack_webhook_url` |
| Discord | `discord_webhook_url` |
| Telegram | `telegram_bot_token`, `telegram_chat_id` |

---

## Case Management

### Severities
low, medium, high, critical

### Statuses
open, investigating, resolved, closed

### Features
- Create from CLI or auto-created from SIEM alerts (severity >= 4)
- Link investigations to cases
- IOC management (ip, domain, url, hash, email, filepath)
- Evidence file attachments
- Timeline with event types: alert, note, investigation, evidence
- Export: JSON, PDF (A4, professional layout)
- Assign to analysts
- Tags and resolution notes

---

## Server & API

### REST Endpoints
| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/register` | POST | API Key | Register edge node |
| `/api/v1/heartbeat` | POST | API Key | Edge node heartbeat |
| `/api/v1/push` | POST | API Key | Push investigation from edge |
| `/api/v1/nodes` | GET | API Key | List nodes |
| `/api/v1/investigations` | GET | API Key | List investigations |
| `/api/v1/investigations/{id}` | GET | API Key | Investigation detail |
| `/api/v1/correlations` | GET | API Key | Cross-node IOC correlations |
| `/health` | GET | None | Health check |

### Edge Sync
- Syncs every 30 seconds
- Cross-node IOC correlation:
  - 1 node: 0.5 confidence
  - 2 nodes: 0.75
  - 3+ nodes: 0.9

---

## Internationalization

| Code | Language |
|------|----------|
| `en` | English |
| `my` | Myanmar (Burmese) |

Auto-detected via `LANG`, `LC_ALL`, `LC_MESSAGES`.

---

## LLM Planner Providers

| Provider | Default Model |
|----------|---------------|
| OpenAI | `gpt-4` |
| Anthropic | `claude-3-haiku-20240307` |
| Ollama | `llama3` |

---

## Database

SQLite in WAL mode. Single file (`~/.trace/trace.db`).

### Tables (14)
investigations, tasks, results, cache, config, events, alerts, response_actions, hunts, cases, case_events, case_iocs, case_evidence, case_investigations

---

## Key Metrics Summary

| Metric | Value |
|--------|-------|
| Version | v0.1.1 |
| Detection rules | 496 total (446 Wazuh + 16 built-in + 34 K8s) |
| Log decoders | 9 built-in + 1,567 Wazuh decoder definitions |
| Agents | 7 core |
| Playbooks | 26 |
| Compliance frameworks | 8 |
| EDR providers | 3 |
| YARA rules | 15 |
| Rootkit patterns | 271 files + 76 trojan signatures |
| MITRE techniques | 81 |
| Languages | 2 (EN + MY) |
| External dependencies | 0 |
| Database | SQLite, single file |
| Binary size | ~10 MB |
