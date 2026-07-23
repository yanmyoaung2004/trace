# CLI Reference

Global flags: `-c, --config string` — path to config file (optional)

Aliases: `trace inv` = investigate, `trace st` = status, `trace hist` = history

Interactive mode: run any of these commands without arguments for an interactive prompt menu.

---

## `init`

First-run setup wizard.

```
trace init
```

Prompts for VT API key, LLM provider URL+key, web search key, SIEM enable, telemetry opt-in.
Creates `~/.trace/config.json`. All prompts are skippable.

---

## `serve`

Start the investigation daemon.

```
trace serve [flags]
```

| Flag            | Default | Description                                                    |
| --------------- | ------- | -------------------------------------------------------------- |
| `--siem`        | `false` | Enable SIEM log monitoring                                     |
| `--syslog-addr` | `:514`  | Syslog listener address                                        |
| `--log-dir`     |         | Directories to watch for log files                             |
| `--export`      |         | Start HTML report server (e.g. `:8081`)                        |
| `--server-addr` |         | Central server address for edge sync (e.g. `http://host:8080`) |

Starts task worker loop (claims + executes tasks from DB), optional SIEM engine,
optional report exporter, optional edge sync client.

---

## `server`

Start in central server mode with web dashboard and sync API.

```
trace server [flags]
```

| Flag          | Default | Description                  |
| ------------- | ------- | ---------------------------- |
| `--http-addr` | `:8080` | HTTP API + dashboard address |
| `--tls-cert`  |         | TLS certificate file path    |
| `--tls-key`   |         | TLS private key file path    |

Edge nodes connect via `serve --server-addr`. Dashboard at `http://<addr>/`.

---

## `investigate`

Run a security investigation.

```
trace investigate [query] [flags]
```

With no query and no `--playbook` flag, opens an interactive prompt that asks for a query
and lets you select a playbook from a list. The selected playbook is used directly (skips
intent classification).

| Flag             | Description                                           |
| ---------------- | ----------------------------------------------------- |
| `-p, --playbook` | Playbook name to run (skips intent classification)    |
| `--param`        | Parameters for the playbook (`key=value`, repeatable) |

Shell completion: `trace investigate --playbook <TAB>` lists available playbooks.

Examples:

```
trace investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
trace investigate --playbook file-analysis --param path=/tmp/malware.exe
trace investigate --playbook domain-reputation --param domain=evil.com
```

Intent classification auto-selects playbook by keyword matching (hash, file, ip, domain, etc.).

v0.2.0 playbooks for remote endpoint actions (requires EDR config):

| Playbook | Description |
|---|---|
| `edr-isolate` | Remotely isolate a host from the network (CS/S1/MDE) |
| `edr-scan` | Trigger a full antivirus scan on a remote endpoint |
| `edr-kill-process` | Kill a process on a remote endpoint by PID |

---

## `status`

View a single investigation's status.

```
trace status <investigation-id>
```

Returns ID, status, intent, playbook, confidence, created/updated timestamps.

---

## `history`

List recent investigations.

```
trace history [flags]
```

| Flag          | Default | Description                      |
| ------------- | ------- | -------------------------------- |
| `-n, --limit` | `20`    | Number of investigations to show |

---

## `report`

Regenerate an investigation report.

```
trace report <investigation-id> [flags]
```

| Flag           | Description              |
| -------------- | ------------------------ |
| `-o, --output` | Save report to file path |

---

## `case`

Manage security cases.

```
trace case <subcommand>
```

With no subcommand, opens an interactive menu (List / Create / View).

Subcommands:
| Command | Description |
|---|---|
| `create --title` | Create a new case (requires `--title`, optional `--description`, `--severity`) |
| `list` | List all cases (filters: `--status`, `--severity`) |
| `view <id>` | View case details with timeline, IOCs, and linked investigations |
| `note <id> <content>` | Add a note to a case |
| `ioc <id> --type --value` | Add an IOC to a case |
| `evidence <id> --file` | Attach an evidence file to a case |
| `assign <id> --to` | Assign a case to an analyst |
| `close <id>` | Close a case |
| `export <id>` | Export a case as JSON with events, IOCs, evidence |
| `export-pdf <id>` | Export a case as PDF |

Shell completion: `trace case view <TAB>` lists case IDs.

---

## `hunt`

Manage automated threat hunts.

```
trace hunt <subcommand>
```

With no subcommand, opens an interactive menu (List / Run / Create).

Subcommands:
| Command | Description |
|---|---|
| `create --name --schedule --playbook` | Create a new scheduled hunt |
| `list` | List all hunts (filter: `--status`) |
| `run <name>` | Execute a hunt immediately |
| `pause <name>` | Pause a scheduled hunt |
| `resume <name>` | Resume a paused hunt |
| `delete <name>` | Delete a hunt |

Shell completion: `trace hunt run <TAB>` lists hunt names.

---

## `approval`

Manage HITL (human-in-the-loop) approval requests.

```
trace approval <subcommand>
```

Subcommands:
| Command | Description |
|---|---|
| `pending` | List investigations waiting for analyst approval |
| `approve <id>` | Approve a pending investigation step |
| `deny <id>` | Deny a pending investigation step |

---

## `plugin`

Manage external agent plugins.

```
trace plugin <subcommand>
```

Subcommands:
| Command | Description |
|---|---|
| `list` | List installed plugins and their capabilities |
| `install <url>` | Download and install a `.so` plugin binary |
| `remove <name>` | Remove an installed plugin |

Plugins are stored in `~/.trace/plugins/` and loaded on next restart.

---

## `update`

Update Trace or its data.

```
trace update <subcommand>
```

Subcommands:
| Command | Description |
|---|---|
| `self` | Download and replace binary with latest release |
| `intel` | Refresh the intel database from release server |
| `playbooks` | Fetch the latest playbook library |

Release downloads from `https://github.com/yanmyoaung2004/trace/releases/latest/download`.
Signature files (`.sig`) are checked if present.

---

## `genkey`

Generate a self-signed TLS certificate and RSA key (development use).

```
trace genkey [flags]
```

| Flag     | Default        | Description                |
| -------- | -------------- | -------------------------- |
| `--host` | `localhost`    | Certificate hostname or IP |
| `--out`  | `~/.trace/tls` | Output directory           |
| `--bits` | `2048`         | RSA key size in bits       |

Outputs `cert.pem` and `key.pem`. Use with `server --tls-cert --tls-key`.

---

## `completion`

Generate shell autocompletion scripts.

```
trace completion <bash|zsh|fish|powershell>
```

Example (powershell):

```powershell
trace completion powershell | Out-String | Invoke-Expression
```

---

## `compliance`

Run compliance scans and generate audit-ready reports (GDPR, HIPAA, PCI DSS, NIST, etc.).
All 464 detection rules are mapped to compliance frameworks via MITRE ATT&CK — SIEM alerts
automatically contribute to compliance scores.

```
trace compliance <subcommand>
```

Subcommands:
| Command | Description |
|---|---|
| `report --framework` | Generate compliance report (text/HTML/MD/JSON) |
| `assess --framework --control --status` | Manually assess a control (pass/fail/na) with justification |
| `evidence --framework --control --description` | Attach evidence file or description to a control |
| `frameworks` | List all 8 supported frameworks |

Supported frameworks:
`pci_dss_v4.0`, `pci_dss_v3.2.1`, `hipaa`, `gdpr`, `nist_sp_800-53`, `iso_27001-2013`, `soc_2`, `cis_csc_v8`

Compliance data sources:
- **SCA scans** — CIS benchmark checks mapped to frameworks
- **Detection rules** — 464 rules mapped via MITRE ATT&CK to PCI DSS/HIPAA/GDPR/NIST/ISO 27001/SOC 2
- **Manual assessments** — `assess` command for non-automated controls

Examples:

```powershell
trace compliance frameworks
trace compliance report --framework pci_dss_v4.0
trace compliance report --framework hipaa -o hipaa-report.html
trace compliance assess --framework gdpr --control Art.32 --status pass --notes "AES-256 encryption in use"
trace compliance evidence --framework nist_sp_800-53 --control AC-17 --description "VPN config" --file vpn-policy.pdf
trace compliance report --framework gdpr -o gdpr-report.md
```

---

## `edr`

Manage EDR agents and dispatch remote actions. Connects to a running Trace server.

```
trace edr <subcommand> [args] [flags]
```

Global flags (apply before subcommand):
| Flag | Env | Description |
|------|-----|-------------|
| `--server` | `TRACE_SERVER_URL` | Trace server URL (default `http://localhost:8080`) |
| `--api-key` | `TRACE_API_KEY` | API key for server authentication |

Subcommands:
| Command | Description |
|---------|-------------|
| `list` | List active EDR agents (use --all to include revoked) |
| `view <agent-id>` | View agent details and status — shows CPU name, memory in GB |
| `events <agent-id>` | View recent events from an agent — supports --type, --min-severity, --limit |
| `dispatch <agent-id> <action> [target]` | Send a response action to an agent |
| `dismiss <alert-id>` | Mark an alert as false positive (trains FP learning) — supports --reason |
| `revoke <agent-id>` | Revoke and remove an agent |

Dispatch actions:
| Action | Target | Extra Flags |
|--------|--------|-------------|
| `kill_process` | PID or process name | `--pid N` or pass name as target |
| `quarantine_file` | File path | `--path /path/to/file` |
| `block_ip` | IP address | `--ip 192.168.1.1` |
| `run_script` | Script content | `--script "cmd"` |
| `isolate_host` | Hostname | No extra flags |
| `collect_forensics` | (optional) | No extra flags |
| `system_snapshot` | (optional) | No extra flags |

Examples:
```powershell
trace edr list
trace edr view abc123
trace edr events abc123 --type alert --min-severity 3 --limit 10
trace edr dispatch abc123 kill_process --pid 4521
trace edr dispatch abc123 quarantine_file --path /tmp/malware.exe
trace edr dispatch abc123 block_ip --ip 203.0.113.42
trace edr dispatch abc123 isolate_host
trace edr dismiss a1b2c3d4-e5f6-7890-abcd-ef1234567890 --reason "Legitimate admin activity"
```

## `trace-agent` (separate binary)

The `trace-agent` binary is deployed to endpoints for local monitoring.

```
trace-agent [flags]
```

| Flag | Env | Description |
|------|-----|-------------|
| `--config` | — | Path to config file (default `~/.trace-agent/config.json`) |
| `--server` | `TRACE_AGENT_SERVER` | Trace server URL |
| `--api-key` | `TRACE_AGENT_API_KEY` | API key for agent registration |
| `--install` | — | Install as system service (Windows SCM or systemd) |
| `--uninstall` | — | Remove system service |
| `--service` | — | Run as Windows service (used by SCM) |
| `--verbose` | — | Enable verbose/debug logging |
| `--version` | — | Print version |

### Agent configuration (`~/.trace-agent/config.json`)

| Field | Default | Description |
|-------|---------|-------------|
| `server_url` | `https://127.0.0.1:8080` | Trace server URL |
| `poll_interval` | `5s` | Action polling interval |
| `heartbeat_interval` | `30s` | Heartbeat interval |
| `batch_interval` | `2s` | Event batch interval |
| `max_batch_size` | `100` | Max events per batch |
| `event_queue_size` | `10000` | Max queued events |
| `monitor_process` | `true` | Enable process monitoring |
| `monitor_file` | `true` | Enable file monitoring |
| `monitor_network` | `true` | Enable network monitoring |
| `monitor_registry` | (windows only) | Enable registry monitoring |
| `data_dir` | `~/.trace-agent/data` | Data directory |
| `tls_cert_file` | — | mTLS client certificate |
| `tls_key_file` | — | mTLS client key |
| `ca_file` | — | CA certificate for verification |

### Monitoring modules

| Module | Linux | Windows | macOS |
|--------|-------|---------|-------|
| **Process** | netlink proc connector (real-time) /proc polling fallback | ETW (real-time) / WMI polling fallback | ps polling |
| **File** | inotify (real-time) + fanotify (file open) + polling fallback | ReadDirectoryChangesW (real-time) + polling fallback | polling |
| **Network** | ss polling | netstat polling | lsof polling |
| **Memory** | /proc/[pid]/maps + mem YARA scan | VirtualQueryEx + ReadProcessMemory + YARA | — |
| **YARA** | 17 rules + external .yar loader (EICAR, PS encoded, cmd abuse, base64, entropy, PE packer, XOR, packed PE, proc injection, keylogger, ransomware, VM escape, Minikatz, CobaltStrike, etc.) | same | same |

### Response actions

| Action | Description |
|--------|-------------|
| `kill_process` | Kill by PID or name via taskkill/kill/pkill |
| `quarantine_file` | Move to isolated directory + chmod 0400 |
| `block_ip` | Firewall rule via netsh/iptables/pfctl |
| `run_script` | Execute script with timeout |
| `isolate_host` | Block all non-Trace traffic |
| `release_host` | Restore network access |
| `collect_forensics` | Snapshot processes, network, disk, memory |
| `system_snapshot` | Lightweight system status |

### Communication security
- Bearer token + HMAC-signed request body
- Optional mTLS with client certificate + CA verification
- Exponential backoff (max 30s, 5 retries)
- Circuit breaker (5 failures → open 60s)

---

## `version`

Print version information.

```
trace version
```
