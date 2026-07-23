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

## Gaps — Status (Updated 2026-07-23)

| Gap | Status | What was built | Tests |
|-----|--------|----------------|-------|
| **File Integrity Monitoring (FIM)** | ✅ **10/10** | SQLite-backed SHA-256 baseline, hash diff detection (fim_added/fim_modified/fim_deleted), permission change detection, flapping suppression (3-change threshold), auto-exclude SQLite files, WAL mode, Stop() race fix, delete pruning | 6 tests |
| **Vulnerability detection** | ✅ **10/10** | Package collection (dpkg/rpm/pacman/WMI), 18 built-in CVEs (xz backdoor, OpenSSH regreSSHion, OpenSSL, glibc, nginx, curl, apache, etc.), NVD feed sync (UpdateCVEDB from any URL), pre-release version handling (2.0-beta < 2.0), config wiring (VulnMinCVSS, VulnScanHours), `trace edr vuln list` CLI + server endpoint | 11 tests, 168 Windows pkgs live |
| **Windows Event Log channels** | ✅ **9/10** | Multi-channel polling: PowerShell (4104/4103), Sysmon (1-22), Task Scheduler (106/140/141), SCM (7045), RDP (21/24). 30s cmd timeout, 50k dedup eviction, dedup key includes EventID (prevents timestamp collision), English locale fallback via Get-WinEvent property indexing | integrated in agent |
| **Hardened Linux agent** | ✅ **9/10** | Netlink reconnection with exponential backoff (1s→30s max), procEventExec + procEventExit handling, /proc polling jitter (±25%), fanotify → inotify → polling 3-level fallback chain. Fanotify: FAN_OPEN/ACCESS/CLOSE_WRITE/OPEN_EXEC all mapped correctly (was using wrong types). Inotify: watch limit check /proc/sys/fs/inotify/max_user_watches | cross-compile verified |
| **Network traffic analysis** | ✅ **10/10** | Suricata eve.json decoder in SIEM engine. Parses alert, DNS, HTTP, TLS, flow events. Maps Suricata severity (1-4) to Trace (7/5/3/1). All timestamp formats: nanosecond, Z suffix, no-colon offset, RFC3339 | 6 tests |
| **Alerting channels** | ✅ **10/10** | Email via SMTP (port 465 SMTPS + 587 STARTTLS), PagerDuty Events API v2 with SHA-256 dedup, generic webhook with custom method/body. Retry logic: 3 attempts on network errors, HTTP 429 (rate limit) retry with 1s/2s/3s, HTTP 5xx retry, HTTP 4xx fail fast. Configurable API base URLs for testing | 14 httptest tests |
| **RBAC multi-tenant** | ✅ **10/10** | adminOnly middleware (role check), `trace admin` CLI (org create/list, user create/list, key rotate), org_id on all 8 tables (server_users, edr_agents, edr_events, server_nodes, server_investigations, server_correlations, edr_actions, edr_fp_counters), org-scoped event/agent queries, user audit ID in auth context, user management API (POST/GET /api/v1/admin/users, POST /api/v1/admin/users/{email}/rotate-key) | API verified |
| **Compliance reporting** | ✅ **10/10** | Score history via JSONL snapshots, `trace compliance trend` CLI with ASCII bar chart + trend direction, server-side snapshot recording (POST /api/v1/compliance/snapshot), ReportEngine.Hostname auto-detection, auto-push to server from CLI | live verified (85% PCI DSS) |
| **Scalable storage** | ❌ Skipped | Architecture decision — SQLite single-file. See notes below | N/A |

## Philosophical Difference

| Dimension | Wazuh | Trace |
|-----------|-------|-------|
| Deployment | Enterprise: server + indexer + dashboard + agents + Docker/K8s | Single binary, zero deps, 10MB, starts in 1 second |
| Scaling | Elasticsearch cluster, multi-node, handles TBs | SQLite single-file, handles ~100GB |
| Ease of use | Heavy setup, requires tuning | One command, works offline, no config needed |
| Trade-off | Powerful but complex | Simple but less scalable |

## Implementation Summary

All 8 gap features implemented across 4 phases (A-D) plus depth fixes:

| Phase | Features | Commits |
|-------|----------|---------|
| **A** | FIM + Windows Event Log channels | a2a5a99 |
| **B** | Vulnerability detection + Alerting channels | 375f30b |
| **C** | NIDS (Suricata decoder) + Linux netlink hint | 138724d |
| **D** | Compliance trending + RBAC | 78ea12a |
| **Depth fix 1** | Critical bugs: goroutine leaks, fanotify→inotify fallback, agent auth | cbca61b |
| **Depth fix 2** | Netlink reconnection, exec events, /proc jitter | df4dce6 |
| **Depth fix 3** | Vuln config wiring, edr vuln CLI | fe95f24 |
| **Depth fix 4** | RBAC admin middleware, user/org API | 35a5b06 |
| **Depth fix 5** | Notifier retries, compliance Hostname | 0a37e0e |
| **Depth fix 6** | RBAC admin CLI, NVD sync, vuln tests, notifier tests | 5836265 |
| **Depth fix 7** | Compliance snapshot API, org_id all tables, user audit | aa14547 |
| **Depth fix 8** | Fix fanotify event types, inotify limit check, locale fallback | 57d2bfa |

**Test coverage added:** FIM (6), vuln scanner (11), notifier (14), Suricata decoder (6) = 37 new tests
**Total pass:** 16/16 test packages, `go vet` clean, cross-compile verified (linux/windows/amd64)
