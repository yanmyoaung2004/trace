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
| `view <id>` | View case details with timeline and IOCs |
| `note <id> <content>` | Add a note to a case |
| `ioc <id> --type --value` | Add an IOC to a case |
| `assign <id> --to` | Assign a case to an analyst |
| `close <id>` | Close a case |
| `export <id>` | Export a case as JSON |
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

## `version`

Print version information.

```
trace version
```
