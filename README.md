<p align="center">
  <img src="docs/assets/logo.png" alt="Trace" width="200">
  <br><br>
  <b>Trace — One binary. Full SOC.</b><br><br>
    <img src="https://img.shields.io/badge/Build-passing-3fb950?style=for-the-badge&logo=go" alt="Build">
    <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go" alt="Go 1.26">
    <img src="https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-8A2BE2?style=for-the-badge" alt="Platforms">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="MIT">
  <br><br>
  <b>Trace</b> is an open-source cybersecurity operations platform that fits in one binary.<br>
  It watches logs, detects threats, enriches indicators, runs investigations, and responds — automatically.<br><br>
  No Docker required. No Python runtime. No Elasticsearch cluster. No SIEM license fees.<br>
  Just a single statically-linked Go binary that runs anywhere.
</p>

## Why Trace?

Most SOC tools fall into two camps:

- **Enterprise SIEMs** (Splunk, Sentinel, QRadar) — powerful but expensive, complex, need a team to maintain
- **Open-source SIEMs** (Wazuh, Security Onion) — better, but still need multiple services, agents, and significant infrastructure

Trace is different. It's an **all-in-one SOC platform** that fits in 10MB:

```
┌──────────────────────────────────────────────────┐
│  File Watcher → Decoder (1,567 formats)          │
│  → Rule Engine (462 rules with MITRE mapping)    │
│  → Alert → Investigation → Playbook → Response   │
│  → Case Management → PDF Report                  │
└──────────────────────────────────────────────────┘
```

No agents to deploy. No databases to tune. One command, and you have a working SOC.

---

## Quick Start

```bash
git clone https://github.com/yanmyoaung2004/trace.git
cd trace
go build -o trace ./cmd/trace

# Run your first investigation (no setup needed)
./trace investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Start the SIEM engine
./trace serve --siem --log-dir /var/log
```

That's it. No config files, no API keys, no containers. The built-in IOC database detects Mimikatz, CobaltStrike, Emotet, Ryuk, WannaCry, and other malware — right out of the box.

---

## What Trace Does

### 🔍 Real-Time SIEM

| Capability      | Detail                                                                            |
| --------------- | --------------------------------------------------------------------------------- |
| Log ingestion   | File watcher + syslog (UDP/TCP)                                                   |
| Decoders        | 1,567 formats: JSON, Syslog, Apache, Windows EVTX, CSV, K8s audit, Wazuh decoders |
| Detection rules | 446 Wazuh-derived + 16 built-in — all with MITRE ATT&CK mapping                   |
| Correlation     | Windowed, threshold-based, suppression                                            |
| Alerting        | Auto-creates investigations and cases for severity ≥ 4                            |

### 🧠 Multi-Agent SOAR

| Agent        | What it does                                                                          |
| ------------ | ------------------------------------------------------------------------------------- |
| **Dispatch** | Orchestrates investigations, classifies intents, plans playbooks, synthesizes reports |
| **Sift**     | YARA scanning, PE analysis, hash lookup, VirusTotal, rootkit detection                |
| **Archive**  | MITRE ATT&CK (750 techniques), CVE lookup, IOC enrichment, web search                 |
| **Response** | Block IP, quarantine files, kill processes, restart services — with rollback          |
| **SCA**      | CIS benchmark compliance scanning (64 policies, auto-detect OS)                       |

### 🔗 Threat Intelligence

| Source               | Cached        | Rate-limited      |
| -------------------- | ------------- | ----------------- |
| VirusTotal           | ✅ 1hr TTL    | ✅ 15s interval   |
| AbuseIPDB            | ✅ 1hr TTL    | ✅ 200ms interval |
| AlienVault OTX       | ✅ 1hr TTL    | ✅ 200ms interval |
| Firecrawl web search | ❌            | N/A               |
| Built-in IOC DB      | ✅ 30-day TTL | N/A               |

### 🎯 Proactive Hunting

Schedule playbooks to run automatically:

```bash
trace hunt create --name nightly-scan \
  --playbook rootkit-scan \
  --schedule 6h

trace hunt list
```

Ships with 3 default hunts: malware scan, compliance audit, rootkit sweep.

### 🛡️ Response Actions

| Action          | Scope                              | Rollback           |
| --------------- | ---------------------------------- | ------------------ |
| Block IP        | iptables, netsh, pfctl             | ✅                 |
| Quarantine file | OS-level move + chmod              | ✅                 |
| Kill process    | By PID or name                     | ❌ (cannot unkill) |
| Restart service | systemctl, sc, launchctl           | ✅ (idempotent)    |
| EDR isolate     | CrowdStrike, SentinelOne, Defender | ✅                 |

## Architecture

```
                    User Query
                       │
                 Dispatch Agent
              (Planner / Orchestrator)
                       │
        ┌──────────────┴──────────────┐
        │                             │
    Archive Agent               Sift Agent
   (Threat Intel)           (Malware Analysis)
        │                             │
    MITRE ATT&CK                 YARA + PE
    CVE Database                 VirusTotal
    Web Search                   Rootkits
        │                             │
        └──────────────┬──────────────┘
                       │
              ┌────────┴────────┐
              │                 │
         SIEM Engine      Response Agent
      462 rules, 7       Block, quarantine,
      decoders, alerts   kill, EDR, rollback
              │                 │
              └────────┬────────┘
                       │
              Investigation + Case
              (Timeline, IOCs, Report, PDF)
```

## Ingested From Wazuh

Trace converts Wazuh's detection engine into embedded Go code:

| Component          | Source                      | Count                           |
| ------------------ | --------------------------- | ------------------------------- |
| Detection rules    | Wazuh XML → Trace rules     | 446 of 3,111                    |
| Log decoders       | Wazuh XML → Trace decoders  | 1,567 with parent/child chains  |
| CIS policies       | Wazuh YAML → SCARunner      | 64 policies                     |
| Rootkit signatures | Wazuh text → RootkitScanner | 271 files + 76 trojans          |
| MITRE data         | Official STIX bundle        | 750 techniques, 267 mitigations |

Re-run `go run ./tools/wazuh-converter/` to refresh from a newer Wazuh release.

## Configuration

```bash
export TRACE_VT_API_KEY="your-key"          # VirusTotal
export TRACE_ABUSEIPDB_KEY="your-key"       # AbuseIPDB
export TRACE_OTX_API_KEY="your-key"         # AlienVault OTX
export TRACE_LLM_API_KEY="your-key"         # OpenAI / Anthropic / Ollama
export TRACE_LLM_URL="https://api.openai.com/v1/chat/completions"
export TRACE_LLM_MODEL="gpt-4"
```

Run `./trace init` for the interactive setup wizard.

## CLI Commands

| Command / Alias                               | Description                                         |
| --------------------------------------------- | --------------------------------------------------- |
| *(none)*                                      | Full-screen terminal UI (TUI) with 5 screens        |
| `init`                                        | First-run setup wizard                              |
| `serve`                                       | Start daemon with SIEM, hunts, edge sync            |
| `server`                                      | Start central server with dashboard + API           |
| `investigate` / `inv`                        | Run an investigation (prompts if no args)           |
| `status` / `st`                               | View investigation status                           |
| `history` / `hist`                            | List recent investigations                          |
| `report`                                      | View investigation report                           |
| `case`                                        | Case management (prompts if no subcommand)          |
| `hunt`                                        | Threat hunting (prompts if no subcommand)           |
| `approval pending/approve/deny`               | Human-in-the-loop                                   |
| `completion`                                  | Generate shell completion scripts                   |
| `plugin search/list/install/remove`           | Plugin ecosystem                                    |
| `update self/intel/playbooks/rollback`        | Self-update                                         |
| `version`                                     | Print version                                       |

## Benchmarks

```
Full pipeline SIEM (SSH brute force):  10,000 events/sec
Full pipeline SIEM (HTTP error):       25,000 events/sec
Rule matching engine:                  500,000 events/sec
All decoders (7, concurrent):          150,000 events/sec
YARA scan (EICAR):                     16,000 ops/sec
Hash lookup (cached):                  34,000 ops/sec
```

## Documentation

| Document                                         | Description            |
| ------------------------------------------------ | ---------------------- |
| [User Guide](docs/user-guide.md)                 | End-to-end walkthrough |
| [CLI Reference](docs/cli-reference.md)           | All commands and flags |
| [Playbook Authoring](docs/playbook-authoring.md) | YAML playbook format   |
| [Plugin Development](docs/plugin-development.md) | Building plugins       |
| [Build Plan](docs/build-plan.md)                 | Development roadmap    |
| [v0.2.0 Plan](docs/v0.2.0-plan.md)               | Next version roadmap   |

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Built with Go, SQLite, YARA, and the MITRE ATT&CK framework.<br>
  <a href="https://github.com/yanmyoaung2004/trace/issues">Issues</a> ·
  <a href="https://github.com/yanmyoaung2004/trace/discussions">Discussions</a> ·
  <a href="SECURITY.md">Security</a>
</p>
