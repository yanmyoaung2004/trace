<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo.png">
    <img src="docs/assets/logo.png" alt="Trace" width="300">
  </picture>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Build-passing-3fb950?style=for-the-badge&logo=go" alt="Build">
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go" alt="Go 1.26">
  <img src="https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-8A2BE2?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="MIT">
</p>

<p align="center">
  <b>Trace</b> is an open-source, multi-agent cybersecurity investigation platform.
  It orchestrates specialized security agents to triage threats, enrich indicators,
  analyze malicious files, monitor logs in real time, and automate response actions —
  all from a single binary.
</p>

<p align="center">
  <a href="#quick-start"><b>Quick Start</b></a> ·
  <a href="#playbooks"><b>Playbooks</b></a> ·
  <a href="#agents"><b>Agents</b></a> ·
  <a href="#cli-reference"><b>CLI</b></a> ·
  <a href="docs/user-guide.md"><b>User Guide</b></a> ·
  <a href="docs/cli-reference.md"><b>CLI Reference</b></a> ·
  <a href="docs/build-plan.md"><b>Build Plan</b></a>
</p>

---

## Features

| Capability             | Description                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| **Threat Triage**      | Investigate hashes, files, IPs, domains, emails, and network indicators with a single command      |
| **YARA + PE Analysis** | Built-in YARA engine with real malware rules; full PE parser (sections, imports, entropy)          |
| **SIEM Monitoring**    | File watcher, syslog (UDP/TCP), 7 log decoders, 462 correlation rules with auto-triggered playbooks |
| **Intel Enrichment**   | Built-in IOC database (22 entries) + AbuseIPDB, AlienVault OTX, VirusTotal, Firecrawl              |
| **MITRE ATT&CK**       | 750 techniques, 267 mitigations, all tactics — offline lookup                                      |
| **SOAR Actions**       | Block IP (firewall), quarantine files, kill processes, restart services — with full rollback       |
| **Human-in-the-Loop**  | Playbook steps can pause for analyst approval before executing actions                             |
| **Central Server**     | Team dashboard with investigation list, search, detail views, cross-node IOC correlation           |
| **Edge Sync**          | Distributed deployment — edge nodes push investigations to central server                          |
| **Notifications**      | Slack and Discord webhook alerts for automated incident notification                               |
| **Plugin System**      | Extend with external `.so` plugins loaded at runtime                                               |
| **Docker Ready**       | Multi-stage Dockerfile + docker-compose for one-command deployment                                 |
| **Wazuh Rules**        | 446 Wazuh detection rules with MITRE mapping and windowed correlation                              |
| **Wazuh Decoders**     | 1,567 log decoder definitions for 120+ log formats with parent/child chaining                     |
| **Rootkit Scanner**    | 271 rootkit file signatures + 76 trojan binary signatures with global filesystem scanning          |
| **SCA Compliance**     | 64 CIS benchmark policies with OS auto-detection (Windows, Linux, macOS)                          |
| **EVTX Parsing**       | Native Windows Event Log XML + Sysmon event ID mapping (25+ Sysmon event types)                   |
| **LLM Planner**        | OpenAI, Anthropic Claude, Ollama — configurable model per provider                                 |

---

## Quick Start

### Build from source

```bash
git clone https://github.com/yanmyoaung2004/trace.git
cd trace
go build -o trace ./cmd/trace
```

### Run your first investigation

```bash
# Check a known malicious hash (Mimikatz)
./trace investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Check a domain reputation
./trace investigate --playbook domain-reputation --param domain=evil.com

# Analyze a file with YARA
./trace investigate --playbook file-analysis --param path=/tmp/suspicious.exe
```

### Setup API keys (optional — local analysis works without them)

```bash
./trace init
```

Interactive wizard prompts for VirusTotal, AbuseIPDB, AlienVault OTX, LLM provider, and web search keys.

### Start the daemon

```bash
# Edge mode with SIEM log monitoring
./trace serve --siem --log-dir /var/log

# Central server mode with web dashboard
./trace server --http-addr :8080

# Edge mode syncing to central server
./trace serve --server-addr http://server-host:8080
```

### Docker

```bash
docker compose up server
# Dashboard at http://localhost:8080
```

---

## Playbooks

Trace ships with **23 built-in playbooks** — YAML workflows that chain agent actions into repeatable investigation procedures.

| Category       | Playbook                 | Purpose                                          |
| -------------- | ------------------------ | ------------------------------------------------ |
| **Triage**     | `hash-lookup`            | Check hash against cache, YARA, VT, and intel DB |
|                | `file-analysis`          | Hash + YARA scan + PE metadata + IOC enrichment  |
|                | `ip-reputation`          | IP address lookup via VT, AbuseIPDB, OTX, intel  |
|                | `domain-reputation`      | Domain/URL check via VT, IOC enrich, web search  |
|                | `email-analysis`         | Analyze phishing email indicators                |
|                | `network-scan`           | Multi-indicator network analysis                 |
| **Enrichment** | `ip-enrich`              | Deep IP enrichment — AbuseIPDB + OTX + VT + IOC  |
|                | `full-enrich`            | Full indicator enrichment across all sources     |
|                | `windows-event-analysis` | Enrich Windows Event with MITRE, CVE, web search |
|                | `registry-check`         | Analyze registry persistence indicators          |
|                | `log-analysis`           | Log event analysis with YARA, MITRE, CVE         |
|                | `mitre-lookup`           | MITRE ATT&CK technique details                   |
|                | `cve-lookup`             | CVE severity, CVSS score, affected products      |
|                | `rootkit-scan`           | Scan for rootkit files and trojan binaries       |
| **Compliance** | `compliance-scan`        | Run CIS benchmark against the current system     |
| **Response**   | `block-ip`               | Firewall rule via netsh/iptables/pfctl           |
|                | `quarantine-file`        | Move file to restricted directory                |
|                | `kill-process`           | Terminate process by name or PID                 |
|                | `restart-service`        | Restart system service                           |
|                | `rollback-action`        | Undo a previously executed response action       |
| **Notify**     | `slack-notify`           | Send alert to Slack webhook                      |
|                | `discord-notify`         | Send alert to Discord webhook                    |

Playbooks support variable interpolation (`${input.hash}`), conditional execution (`if:`), timeouts, optional steps, and human-in-the-loop gates (`wait: analyst_approval`).

---

## Agents

| Agent         | Package                          | Capabilities                                                                   |
| ------------- | -------------------------------- | ------------------------------------------------------------------------------ |
| **Sift**      | `internal/sift`                  | YARA scan, PE analysis, hash lookup, VirusTotal, rootkit scanning              |
| **Archive**   | `internal/archive`               | MITRE ATT&CK (750 techniques), CVE lookup, IOC enrichment, web search          |
| **Dispatch**  | `internal/dispatch`              | Intent classification, playbook planning, LLM planner, report synthesis        |
| **Response**  | `internal/response`              | Block IP, quarantine file, kill process, restart service, rollback             |
| **Notifier**  | `internal/integration/notifier`  | Slack webhook, Discord webhook                                                 |
| **AbuseIPDB** | `internal/integration/abuseipdb` | IP reputation with abuse confidence score                                      |
| **OTX**       | `internal/integration/otx`       | AlienVault OTX pulse count for hash, IP, domain, URL                           |
| **SCA**       | `internal/plugins/sca`           | CIS benchmark compliance scanning with OS auto-detection                       |
| **Splunk**    | `internal/integration/splunk`    | Splunk search, saved search, alert check                                       |
| **Elastic**   | `internal/integration/elastic`   | Elasticsearch search, alert check, index listing                               |
| **Exporter**  | `internal/plugins/exporter`      | HTML report server for investigation dashboards                                |

All agents implement the `agent.Agent` interface and are registered in a shared plugin registry at startup.

---

## CLI Reference

| Command                                  | Description                                                                        |
| ---------------------------------------- | ---------------------------------------------------------------------------------- |
| `init`                                   | First-run setup wizard (API keys, SIEM, telemetry, PATH setup)                   |
| `serve`                                  | Start edge daemon — task worker, SIEM, export server, edge sync                    |
| `server`                                 | Start central server — web dashboard, sync API, RBAC, correlations                |
| `investigate <query>`                    | Run an investigation (natural language or playbook)                               |
| `status <id>`                            | View investigation status                                                          |
| `history`                                | List recent investigations                                                         |
| `report <id>`                            | Regenerate or save investigation report                                            |
| `approval pending\|approve\|deny <id>`   | Human-in-the-loop approval workflow                                                |
| `plugin search\|list\|install\|remove`   | Search registry, list, install, remove plugins                                    |
| `update self\|intel\|playbooks\|rollback`| Update binary, intel DB, playbooks, or rollback to previous version               |
| `genkey`                                 | Generate self-signed TLS certificate and key                                       |
| `completion bash\|zsh\|fish\|powershell` | Generate shell completion scripts                                                  |
| `version`                                | Print version information                                                          |

See [docs/cli-reference.md](docs/cli-reference.md) for full details.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Dispatch Agent                         │
│       Intent Classification → Playbook Matching → Report    │
├──────────┬───────────┬───────────┬───────────┬──────────────┤
│  Sift    │  Archive  │ Response  │ SIEM      │ Plugins      │
│ YARA     │ MITRE     │ block IP  │ 462 rules │ external .so │
│ PE       │ CVE       │ quarantine│ 7 decoders│ SCA          │
│ VT       │ intel     │ kill      │ alerts    │ exporter     │
│ rootkits │ web search│ rollback  │ EVTX/Wazuh│              │
└──────────┴───────────┴───────────┴───────────┴──────────────┘
         │                                            │
         └────────── Edge sync (opt-in) ──────────────┘
                            │
                    ┌───────┴───────┐
                    │   Server      │
                    │  Dashboard    │
                    │  API + RBAC   │
                    │  Correlations │
                    └───────────────┘
```

---

## SIEM Rules

16 built-in + 446 Wazuh-derived rules covering Windows Event Log, syslog, SSH, web servers, Docker, firewalls, cloud platforms:

| Rule                                    | MITRE     | Severity |
| --------------------------------------- | --------- | -------- |
| Multiple failed logins (5 in 60s)       | T1110.003 | 4        |
| Brute force (20 in 60s)                 | T1110     | 5        |
| HTTP 5XX errors                         | —         | 3        |
| HTTP 4XX burst (10 in 60s)              | —         | 2        |
| Suspicious process execution            | T1059     | 4        |
| PowerShell script block (Event 4104)    | T1059.001 | 3        |
| Scheduled task created (Event 4698)     | T1053.005 | 4        |
| New service installed (Event 7045)      | T1543.003 | 4        |
| Windows Defender detection (Event 1116) | T1204     | 5        |
| SSH brute force (6 attempts)            | T1110     | 5        |
| SSH connection timeout                  | T1190     | 4        |
| Apache error                            | —         | 3        |
| Docker container issues                 | —         | 3        |

Rules auto-trigger playbooks. 133 Wazuh rules have mapped playbook actions by MITRE technique.

---

## Configuration

```bash
export TRACE_VT_API_KEY="your-key"          # VirusTotal
export TRACE_ABUSEIPDB_KEY="your-key"       # AbuseIPDB
export TRACE_OTX_API_KEY="your-key"         # AlienVault OTX
export TRACE_LLM_API_KEY="your-key"         # LLM provider
export TRACE_LLM_URL="https://api.openai.com/v1/chat/completions"
export TRACE_LLM_MODEL="gpt-4"              # or claude-3-haiku, llama3
export TRACE_WEB_SEARCH_KEY="your-key"      # Firecrawl
export TRACE_DB_PATH="/path/to/custom/db"
```

Run `./trace init` for the interactive setup wizard.

---

## Development

```bash
go build ./cmd/trace
go vet ./...
go test ./... -short -count=1
```

---

## Documentation

| Document                                               | Description                                                   |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| [User Guide](docs/user-guide.md)                       | End-to-end walkthrough for analysts                           |
| [CLI Reference](docs/cli-reference.md)                 | All commands, flags, and examples                             |
| [Playbook Authoring Guide](docs/playbook-authoring.md) | YAML structure, interpolation, conditions                     |
| [Plugin Development Guide](docs/plugin-development.md) | Building and distributing plugins                             |
| [Testing Guide](docs/testing-guide.md)                 | Verification commands for every phase                         |
| [Build Plan](docs/build-plan.md)                       | Phased implementation roadmap                                 |
| [gRPC Plugin Architecture](docs/grpc-plugin.md)        | Language-agnostic sidecar plugin design                       |

---

## Benchmarks

```
YARA Scan EICAR:       18.8k ops — 61μs/op
Hash Lookup Known:     34.4k ops — 33μs/op
WindowsEvent Decoder:  6.2M ops — 212ns/op
JSON Decoder:          287k ops — 4μs/op
Auto Decoder:          159k ops — 7μs/op
Apache Decoder:        229k ops — 5μs/op
Syslog Decoder:        338k ops — 3μs/op
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Community

- [Issues](https://github.com/yanmyoaung2004/trace/issues) — bug reports and feature requests
- [Discussions](https://github.com/yanmyoaung2004/trace/discussions) — questions and ideas
- [Security](SECURITY.md) — vulnerability reporting
