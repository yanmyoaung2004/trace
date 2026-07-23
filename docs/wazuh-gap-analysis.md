# Trace vs Wazuh — Gap Analysis

## What Trace Already Does (Wazuh-Equivalent)

| Capability | Trace | Wazuh |
|-----------|-------|-------|
| Detection rules | 496 (446 Wazuh-derived + 16 built-in + 34 K8s) | 3,111 |
| Log decoders | 1,567 (imported from Wazuh XML) | 3,000+ |
| SCA compliance | 64 CIS policies, 8 frameworks (464 controls) | CIS + custom policies |
| Endpoint monitoring | Custom agent: process, file, network, memory, USB, DNS, Code Integrity | Agent with all of the above + registry |
| Threat intel | VT, AbuseIPDB, OTX, MITRE (81 techniques), CVE, Firecrawl web | Same + custom feeds |
| SOAR / playbooks | 26 playbooks, auto-investigation from SIEM alerts | Active response scripts |
| Case management | Full with timeline, IOC tracking, PDF export | Web UI-based |
| MITRE ATT&CK mapping | 81 techniques mapped to rules | Full ATT&CK navigator |
| On-agent YARA | 17 rules, pure Go (no libyara C dep) | Via integration |
| Response actions | 8: kill_process, quarantine_file, block_ip, run_script, isolate_host, collect_forensics, system_snapshot, release_host | Active response daemon |
| Custom EDR agent | Self-contained ~10MB Go binary, no third-party EDR required | Must install Wazuh agent |

## Gaps

| Gap | Impact | Effort | Priority |
|-----|--------|--------|----------|
| **File Integrity Monitoring (FIM)** | No baseline hashing, no diff tracking. Wazuh tracks file creates + hash diffs. Trace only detects create/modify/delete. Silent file changes go unnoticed | 3-5 days | **High** |
| **Vulnerability detection** | Cannot scan installed software against CVEs. Wazuh scans system packages (deb/rpm/pacman) and reports known vulnerabilities | 5-7 days | **High** |
| **Windows Event Log channels** | Agent monitors Security log via ETW. Wazuh reads System, Application, PowerShell, Sysmon, Task Scheduler, etc. | 2-3 days | Medium |
| **Hardened Linux agent** | Linux uses /proc polling fallback (netlink available but may fail). Process monitoring is less real-time than Windows ETW path | 3-5 days | Medium |
| **Network traffic analysis** | No pcap or NIDS integration. Wazuh integrates with Suricata for full packet inspection | 2-3 days (plugin) | Low |
| **Alerting channels** | Notifier agent supports Slack, Discord, Telegram. No email, PagerDuty, generic webhook | 1-2 days | Medium |
| **Scalable storage** | SQLite single-file (WAL mode). Wazuh uses Elasticsearch cluster. Trace cannot handle >100GB of log volume or multi-node search | Architecture decision | **Architecture** |
| **RBAC multi-tenant** | Basic RBAC (admin/analyst). No org-level isolation or per-customer data separation | 3-5 days | Low |
| **Compliance reporting** | PDF export for cases. Wazuh has dedicated compliance dashboards with executive summaries, trend charts, and framework-specific reports | 3-4 days | Medium |

## Philosophical Difference

| Dimension | Wazuh | Trace |
|-----------|-------|-------|
| Deployment | Enterprise: server + indexer + dashboard + agents + Docker/K8s | Single binary, zero deps, 10MB, starts in 1 second |
| Scaling | Elasticsearch cluster, multi-node, handles TBs | SQLite single-file, handles ~100GB |
| Ease of use | Heavy setup, requires tuning | One command, works offline, no config needed |
| Trade-off | Powerful but complex | Simple but less scalable |

## Recommended Next Items

1. **FIM** — keeps you honest about file integrity. Detect silent changes to binaries, configs, and system files.
2. **Vulnerability detection** — answers "am I exposed to CVE-2025-XXXXX?" by scanning installed packages.
3. **Windows Event Log channels** — low effort, high value. Expand beyond Security log to System, PowerShell, Sysmon.
4. **Compliance reporting** — generate framework-specific executive summaries with trend data.
