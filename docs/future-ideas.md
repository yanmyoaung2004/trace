# Trace — Future Ideas & Roadmap

> Beyond v0.1.x. Ideas are unordered within categories. Pick what interests you.

---

## Scale & Deploy

| Idea | Effort | Why |
|------|--------|-----|
| **Kubernetes Helm chart** | 2-3 days | One `helm install trace` to deploy server + agents as DaemonSet, with ConfigMap, secrets, HPA |
| **Grafana dashboards** | 1 day | Pre-built dashboards for TSE metrics, alert rates, agent health, storage usage — import via `trace metrics grafana-export` |
| **`trace upgrade` self-update** | 1 day | `trace upgrade` downloads latest server binary, swaps, restarts — same as agent updater but for the server itself |
| **Docker images** | 1 day | Automated multi-arch image builds (linux/amd64, linux/arm64) pushed to GHCR |
| **Systemd service files** | 1 day | `trace init --systemd` generates ready-to-use unit files with proper logging, restart policy, hardening |
| **Terraform module** | 2 days | Provision the full stack (server + agents + S3 + networking) on AWS/GCP/Azure |

---

## Detection & Response

| Idea | Effort | Why |
|------|--------|-----|
| **MISP threat intel feed** | 2 days | Auto-import IOCs (hashes, IPs, domains) from MISP as watchlists + YARA rules. Daily sync |
| **Automated IOC enrichment** | 2 days | When a hash/IP is seen, auto-query VirusTotal + OTX + AbuseIPDB → create case with enrichment |
| **Watchlists** | 1 day | `trace watchlist add --type ip 10.0.0.5` — monitor any event matching a watchlist entry, auto-alert |
| **IOC expiry / lifecycle** | 1 day | Watchlist entries auto-expire after N days. Renew on match |
| **Sigma rule integration** | 3 days | Import Sigma rules (16,000+ community rules) as SIEM detection rules. Sigma→Trace rule converter |
| **Suricata integration** | 2 days | Import Suricata alerts as SIEM events. Run Suricata alongside trace-agent on Linux |
| **File reputation service** | 1 day | `trace hashlookup <sha256>` — check against VirusTotal, OTX, local cache. Returns malicious/suspicious/clean with vendor count |

---

## Agent & Endpoint

| Idea | Effort | Why |
|------|--------|-----|
| **USB device monitoring** | 1 day | Detect USB insertion via `RegisterDeviceNotificationW` (Windows). **Code exists** (`usb_windows.go`) but not wired into agent |
| **ETW channel monitoring** | — | Already implemented. `etw_channels_windows.go` wired into agent |
| **Windows memory scanning** | — | Already implemented. `memory_windows.go` (EnumerateProcesses + ReadProcessMemory) |
| **Process tree tracking** | — | Already implemented. `tree.go` tracks parent-child relationships |
| **Container security** | 2 days | Watch Docker/K8s audit logs. Detect privileged containers, host mounts, `--net=host` |
| **Windows Event Log** | 2 days | Subscribe to Windows Event Log channels (Security, System, PowerShell) and ship as EDR events |
| **macOS agent** | 3 days | Compile for darwin/amd64 + arm64. Basic monitoring (process, file, network) using EndpointSecurity framework |
| **DNS query monitoring** | 2 days | Capture DNS queries (via eBPF on Linux, EventLog on Windows). Detect beaconing, DGA domains |
| **Process memory scanning** | 2 days | Scan process memory for known malicious patterns (Mimikatz, Cobalt Strike) |
| **Binary allowlist/blocklist** | 1 day | `trace policy add --hash sha256:<hash> --action block` — prevent execution of known-bad hashes |
| **Response actions** | — | Already implemented: `kill_process`, `quarantine_file`, `block_ip`, `run_script`, `isolate_host`, `collect_forensics` with rollback support |

---

## Compliance & Reporting

| Idea | Effort | Why |
|------|--------|-----|
| **Scheduled compliance reports** | 1 day | `trace compliance schedule --framework pci_dss_v4.0 --cron "0 6 * * 1"` — weekly email with HTML report |
| **Evidence retention policies** | 1 day | Auto-purge evidence older than N days per framework. Configurable in `compliance evidence --retention 90d` |
| **Custom compliance frameworks** | 1 day | `trace compliance framework import --file custom.json` — upload your own control set (JSON/YAML) |
| **Multi-framework gap analysis** | 1 day | Compare coverage across frameworks: "These 10 controls cover PCI DSS + HIPAA + SOC 2 simultaneously" |
| **Executive summary PDF** | 1 day | `trace compliance report --format pdf` — board-ready PDF with score trend chart and control status table |
| **Remediation tracking** | 2 days | Assign controls to analysts, track pass/fail over time, close findings with evidence |

---

## SIEM & Rules

| Idea | Effort | Why |
|------|--------|-----|
| **Rule editor UI** | 2 days | Web form to create/edit SIEM rules without editing YAML. Test rules against historical data |
| **Rule performance stats** | 1 day | Per-rule metrics: matches/sec, avg match time, false positive ratio. Identify expensive rules |
| **Log source health** | 1 day | Dashboard showing which log sources are sending data, which are silent, lag behind |
| **Alert routing** | 1 day | Route high-severity alerts to Slack, medium to email, low to web only. Per-rule notifier config |
| **MITRE ATT&CK matrix** | 2 days | Visual heatmap showing detected techniques per tactic. Filterable by time range and source |

---

## Storage & TSE

| Idea | Effort | Why |
|------|--------|-----|
| **S3 cold tier as default**| 1 day | Auto-upload Parquet files to S3 after flush. No local cold storage needed |
| **TSE read replicas** | 3 days | Separate read-only TSE instances that tail the WAL. Dashboard queries go to replicas |
| **Query caching** | 1 day | Cache frequent query results (top agent, last hour, severity counts) with 1s TTL |
| **Data retention tiers** | 1 day | Hot: 2h (SQLite), Warm: 30d (local Parquet), Cold: 1y+ (S3/Glacier). Query transparently across tiers |

---

## User Experience

| Idea | Effort | Why |
|------|--------|-----|
| **Mobile-friendly web** | 1 day | Responsive CSS for phone screens. Quick alert acknowledgment on the go |
| **`trace web` CLI** | 1hr | Opens the web dashboard in the default browser from terminal |
| **`trace status`** | 1hr | One-command overview: server health, connected agents, recent alerts, TSE usage |
| **Dark/light theme toggle** | 1hr | Theme switcher in the web UI. Persists preference in localStorage |
| **Alert notifications** | 1 day | Desktop notifications (via `notify-send` on Linux, Toast on Windows) for critical alerts |
| **Multi-language UI** | 2 days | Locale system already exists. Add community translations for Japanese, Korean, Spanish, Arabic |

---

## Internal Architecture

| Idea | Effort | Why |
|------|--------|-----|
| **Pluggable SIEM decoders** | 2 days | Drop a `.so` or `.wasm` decoder in the decoders directory. No recompile needed for new log formats |
| **Plugin marketplace** | 3 days | `trace plugin search`, `trace plugin install crowdstrike` — central registry for community plugins |
| **`trace doctor` diagnostic**| 1 day | `trace doctor` checks config, DB integrity, S3 connectivity, agent connectivity, reports issues |
| **Benchmark suite** | 2 days | `trace benchmark` runs performance tests (write throughput, query latency, YARA scan speed) and outputs comparison table |
| **Canary deployments** | 2 days | Update one agent at a time, monitor for errors, rollback automatically if alert rate spikes |

---

## Summary by Theme

| Theme | Ideas | Effort |
|-------|-------|--------|
| **Deploy & Ops** | Helm chart, Grafana, self-update, Docker images, systemd, Terraform | ~10 days |
| **Detection & Response** | MISP, IOC enrichment, watchlists, Sigma, Suricata, file reputation | ~11 days |
| **Agent & Endpoint** | USB, containers, Windows EventLog, macOS, DNS, memory scanning, allowlist | ~14 days |
| **Compliance & Reporting** | Scheduled reports, retention, custom frameworks, gap analysis, PDF, remediation | ~8 days |
| **SIEM & Rules** | Rule editor UI, performance stats, log health, routing, ATT&CK matrix | ~8 days |
| **Storage & TSE** | S3 default, read replicas, query cache, retention tiers | ~6 days |
| **User Experience** | Mobile web, `trace web`, status, theme, notifications, i18n | ~7 days |
| **Architecture** | Pluggable decoders, plugin marketplace, doctor, benchmark, canary | ~10 days |

---

## Already Built — Not Wired

These 13 features have complete code but are not integrated into the main system.
They're ready to wire — just need to plug them in.

### Monitor Package (`internal/edr_agent/monitor/`)

| Feature | File | What it does | Wire to |
|---------|------|-------------|---------|
| **Kill chain reconstruction** | `killchain.go` | Correlates process/file/network events into kill-chain alerts with confidence scoring | `agent.go` → `analysisLoop()` |
| **Flood detection** | `flood.go` | Detects event floods (too many events/sec) with adaptive thresholds, suppresses during storms | `agent.go` → `analysisLoop()` |
| **Memory scanner** | `memory.go` | Scans process memory for YARA matches via `/proc/pid/mem` (Linux) | `agent.go` → optional monitor |
| **Hash sharing (P2P)** | `hashshare.go` | Peer-to-peer hash verdict sharing via UDP multicast. Share YARA results between agents | `agent.go` → after `scanCache` init |
| **False positive learning** | `fplearn.go` | Auto-throttles noisy YARA rules on specific processes after repeated dismissals | `agent.go` → YARA scan handlers |
| **Entropy baseline** | `entropy.go` | Maintains PE section entropy baselines, detects anomalies via Z-score with time decay | `agent.go` → `analysisLoop()` |
| **Process hollowing (Windows)** | `process_hollowing_windows.go` | Detects process hollowing via PEB base address changes and W^X violations | `agent.go` → under `windows` build |
| **ETW session (alt)** | `etw_windows.go` | Separate ETW tracing session using `StartTraceW`/`OpenTraceW` (different from channel monitor) | `agent.go` → as alt ETW monitor |
| **USB monitor (Windows)** | `usb_windows.go` | Detects USB drive insertion/removal via `RegisterDeviceNotificationW` with polling fallback | `agent.go` → under `windows` conditional |
| **Authenticode verification** | `authenticode_windows.go` | Verifies PE digital signatures via `WinVerifyTrust` API | PE analysis pipeline |
| **AMSI integration** | `amsi_windows.go` | Scans buffers/strings via Windows Antimalware Scan Interface | YARA scanning pipeline |

### Sift Package (`internal/sift/`)

| Feature | File | What it does | Wire to |
|---------|------|-------------|---------|
| **Behavior scan action** | `rootkit_behavior.go` | 8 runtime checks (hidden process, kernel module, fileless malware, container escape, etc.) | `sift.Agent.Execute()` switch or register `RootkitScanner` as standalone plugin |

### Audit Package (`internal/audit/`)

| Feature | File | What it does | Wire to |
|---------|------|-------------|---------|
| **Audit trail logger** | `logger.go` | HMAC-chained, tamper-evident audit log with SQLite persistence and integrity verification | `root.go:initServices()` or server initialization to log admin actions, case mutations, response actions |

### Effort to wire all 13

| Group | Count | Effort |
|-------|-------|--------|
| Simple (one-line start) | 5 (USB, flood, hashshare, fplearn, entropy) | ~2 hours |
| Medium (integrates with pipeline) | 5 (killchain, memory, hollowing, ETW, behavior scan) | ~1 day |
| Complex (requires config + UI) | 3 (authenticode, AMSI, audit) | ~2 days |
| **Total** | **13** | **~3 days** |

**Total: ~74 days of work. Pick what excites you most.**
