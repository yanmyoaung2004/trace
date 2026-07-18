# InnoIgniterAI

Multi-agent cybersecurity investigation platform. Orchestrates agents to investigate threats, enrich IOCs, analyze files, and automate response actions.

## Quickstart

```powershell
cd dev
go build -o innoigniter.exe ./cmd/innoigniter
.\innoigniter.exe init          # first-run setup
.\innoigniter.exe investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```

## CLI Reference

| Command | Description |
|---|---|
| `init` | First-run setup wizard (creates config) |
| `serve` | Start daemon (task worker, SIEM, sync) |
| `server` | Start central server mode (dashboard + API) |
| `investigate <query>` | Run a security investigation |
| `status <id>` | View investigation status |
| `history` | List recent investigations |
| `report <id>` | Regenerate investigation report |
| `approval pending/approve/deny <id>` | HITL approval workflow |
| `plugin list/install/remove` | Manage plugins |
| `update self/intel/playbooks` | Update binary or data |
| `version` | Print version |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Host Agent                         │
│  Intent parsing → Playbook matching → Report gen     │
├────────┬────────┬──────────┬───────────┬─────────────┤
│Detection│Knowledge│Response │  SIEM     │  Plugins    │
│ YARA    │ MITRE   │ block   │  log      │  external   │
│ PE      │ CVE     │ kill    │  decode   │  .so loader │
│ VT      │ intel   │ rollback│  rules    │             │
└────────┴────────┴──────────┴───────────┴─────────────┘
         │                              │
         └────── Edge sync (opt) ───────┘
                        │
                  ┌─────┴─────┐
                  │  Server   │
                  │ dashboard │
                  │ API       │
                  └───────────┘
```

## Playbooks

Built-in playbooks in `internal/playbook/*.yaml`:

- `hash-lookup` — check hash against cache + YARA + VT
- `file-analysis` — extract PE metadata, YARA scan, VT lookup
- `ip-reputation` — check IP against cache + VT + threat intel
- `url-scan` — extract URL indicators, check reputation
- `mitre-lookup` — MITRE ATT&CK technique details
- `cve-lookup` — CVE vulnerability context
- `block-ip` — firewall rule via netsh/iptables/pfctl
- `quarantine-file` — move to restricted directory
- `kill-process` — terminate by name or PID
- `restart-service` — restart system service
- `rollback-action` — undo a previous response action

## Configuration

Config file: `~/.innoigniter/config.json` (created by `init`)

Key env overrides:
- `INNO_VT_API_KEY` — VirusTotal API key
- `INNO_LLM_API_KEY` — LLM provider key
- `INNO_LLM_URL` — LLM endpoint URL
- `INNO_DB_PATH` — SQLite database path

## Cross-compile

```powershell
make cross
```

Builds for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64.

## Development

```powershell
go build ./cmd/innoigniter
go vet ./...
go test ./... -count=1
```
