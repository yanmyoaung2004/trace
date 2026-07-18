# CLI Reference

Global flags: `-c, --config string` — path to config file (optional)

---

## `init`

First-run setup wizard.

```
innoigniter init
```

Prompts for VT API key, LLM provider URL+key, web search key, SIEM enable, telemetry opt-in.
Creates `~/.trace/config.json`. All prompts are skippable.

---

## `serve`

Start the investigation daemon.

```
innoigniter serve [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--siem` | `false` | Enable SIEM log monitoring |
| `--syslog-addr` | `:514` | Syslog listener address |
| `--log-dir` | | Directories to watch for log files |
| `--export` | | Start HTML report server (e.g. `:8081`) |
| `--server-addr` | | Central server address for edge sync (e.g. `http://host:8080`) |

Starts task worker loop (claims + executes tasks from DB), optional SIEM engine,
optional report exporter, optional edge sync client.

---

## `server`

Start in central server mode with web dashboard and sync API.

```
innoigniter server [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--http-addr` | `:8080` | HTTP API + dashboard address |
| `--tls-cert` | | TLS certificate file path |
| `--tls-key` | | TLS private key file path |

Edge nodes connect via `serve --server-addr`. Dashboard at `http://<addr>/`.

---

## `investigate`

Run a security investigation.

```
innoigniter investigate [query] [flags]
```

| Flag | Description |
|---|---|
| `-p, --playbook` | Playbook name to run (skips intent classification) |
| `--param` | Parameters for the playbook (`key=value`, repeatable) |

Examples:
```
innoigniter investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
innoigniter investigate --playbook file-analysis --param path=/tmp/malware.exe
innoigniter investigate --playbook domain-reputation --param domain=evil.com
```

Intent classification auto-selects playbook by keyword matching (hash, file, ip, domain, etc.).

---

## `status`

View a single investigation's status.

```
innoigniter status <investigation-id>
```

Returns ID, status, intent, playbook, confidence, created/updated timestamps.

---

## `history`

List recent investigations.

```
innoigniter history [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-n, --limit` | `20` | Number of investigations to show |

---

## `report`

Regenerate an investigation report.

```
innoigniter report <investigation-id> [flags]
```

| Flag | Description |
|---|---|
| `-o, --output` | Save report to file path |

---

## `approval`

Manage HITL (human-in-the-loop) approval requests.

```
innoigniter approval <subcommand>
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
innoigniter plugin <subcommand>
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
innoigniter update <subcommand>
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
innoigniter genkey [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--host` | `localhost` | Certificate hostname or IP |
| `--out` | `~/.trace/tls` | Output directory |
| `--bits` | `2048` | RSA key size in bits |

Outputs `cert.pem` and `key.pem`. Use with `server --tls-cert --tls-key`.

---

## `completion`

Generate shell autocompletion scripts.

```
innoigniter completion <bash|zsh|fish|powershell>
```

Example (powershell):
```powershell
innoigniter completion powershell | Out-String | Invoke-Expression
```

---

## `version`

Print version information.

```
innoigniter version
```
