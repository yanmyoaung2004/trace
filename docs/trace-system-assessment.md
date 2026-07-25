# Trace — Full System Assessment

---

## Overview

| Metric | Value |
|--------|-------|
| Total packages | **56** |
| Packages with tests | **45** (80%) |
| Packages without tests | **11** (20%) |
| Build (CGO_ENABLED=0) | ✅ Passes |
| `go vet` warnings | ⚠️ 5 unsafe.Pointer in EDR agent |
| Main binary | `cmd/trace` — 27KB+ binary |

---

## Module-by-Module

### 1. TSE Storage Engine (`internal/storage/` — 15 packages)

| | |
|---|---|
| **Rating** | 9/10 |
| **Tests** | ✅ All 15 packages have tests (~120 total) |
| **Races** | ✅ Zero |
| **Verification** | Crash-proven at 500 events, fuzzed 2.3M inputs |
| **Strength** | Complete hot/cold tiered event store with exactly-once semantics. Row-group pruning, DuckDB auto-select. Prometheus metrics, health endpoints, retention enforcement. |
| **Weakness** | Compactor schedule hardcoded. Queue not wired into hot path. No multi-node. |

---

### 2. CLI & Server (`cmd/trace/`, `internal/server/`)

| | |
|---|---|
| **Rating** | 6/10 |
| **Tests** | ❌ No tests for server or CLI |
| **Races** | ❌ Unknown |
| **Strength** | Full CLI with cobra (serve, investigate, case, hunt, tse, compliance, config). HTTP + gRPC API. Dashboard. |
| **Weakness** | **No server tests** — the entire HTTP API, gRPC sync, and dashboard are untested. No handler tests. No request/response validation tests. |

---

### 3. SIEM (`internal/siem/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Has tests (integration + fuzz) |
| **Races** | ✅ Zero |
| **Strength** | EVTX decoder with Sysmon mappings. 464+ detection rules (Wazuh-compatible). Suricata decoder. K8s audit decoder. Fuzzed. |
| **Weakness** | No decoder test for raw syslog. Rule coverage against MITRE ATT&CK not measured. No performance benchmarks for 10K+ EPS. |

---

### 4. Playbook Engine (`internal/playbook/`, `internal/dispatch/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Has tests |
| **Races** | ✅ Zero |
| **Strength** | YAML playbook executor with interpolation. 20+ built-in playbooks. Multi-provider LLM support (OpenAI, Anthropic, Ollama, etc). |
| **Weakness** | LLM dispatch is fragile — errors from LLM calls can break the whole pipeline. No timeout for LLM calls. No caching of LLM responses. |

---

### 5. Case Management (`internal/cases/`)

| | |
|---|---|
| **Rating** | 8/10 |
| **Tests** | ✅ 25 tests |
| **Races** | ✅ Zero |
| **Strength** | Full CRUD for investigations/cases/evidence. Auto-case creation from SIEM alerts. Evidence linking. PDF export. 25 tests covering CRUD, state machine, events, IOCs, evidence, export, edge cases. |
| **Weakness** | No validation of state machine transitions (open→closed→reopen). PDF export has no golden file test. |

---

### 6. Compliance (`internal/compliance/`)

| | |
|---|---|
| **Rating** | 5/10 |
| **Tests** | ❌ No tests |
| **Races** | ❌ Unknown |
| **Strength** | Multi-framework support (GDPR, HIPAA, PCI DSS, NIST, ISO 27001, SOC 2, CIS v8). Framework assessments. Evidence collection. SCA integration. |
| **Weakness** | **No tests at all.** Report generation logic is untested. Framework mappings are untested. |

---

### 7. EDR Agent (`internal/edr_agent/`, `internal/response/`)

| | |
|---|---|
| **Rating** | 6/10 |
| **Tests** | ⚠️ Partial (monitor + response have tests, sub-packages don't) |
| **Vet** | ⚠️ 5 unsafe.Pointer warnings |
| **Strength** | 7 monitors (process, file, network, registry, FIM, vulnerability, ETW). 8 response actions. YARA scanning. mTLS. Auto-update. SCM service. |
| **Weakness** | unsafe.Pointer usage in ETW (Windows). Queue, service, transport, updater sub-packages have no tests. FIM hash baseline only tested at unit level. |

---

### 8. Threat Intel (`internal/archive/`, `internal/integration/`)

| | |
|---|---|
| **Rating** | 6/10 |
| **Tests** | ⚠️ Partial (archive + notifier have tests, integrations don't) |
| **Strength** | MITRE ATT&CK (750 techniques). CVE lookup. AbuseIPDB, OTX, VirusTotal. Slack/Discord/Telegram/email/PagerDuty/webhook alerts. |
| **Weakness** | **5 integration packages have no tests** (AbuseIPDB, OTX, Elastic, Splunk, EDR connectors). No integration test against real APIs. Intel caching (SQLite) tested at integration level only. |

---

### 9. Detection & SIFT (`internal/sift/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Has tests |
| **Races** | ✅ Zero |
| **Strength** | PE analysis. YARA scanning. Hash matching. Rootkit/trojan detection (271 file patterns + 76 signatures). VirusTotal integration. |
| **Weakness** | Rootkit behavioral analysis is untested. No benchmark for YARA compilation time. Static signatures need regular updates. |

---

### 10. Hunt Engine (`internal/hunt/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ 12 tests (CRUD, pause/resume, due hunts, mark run, duplicate name) |
| **Races** | ✅ Zero |
| **Strength** | Scheduled hunting with cron-like scheduler. 3 default hunts. CLI integration. 12 tests covering full CRUD lifecycle. |
| **Weakness** | Scheduler timing untested (complex deps). Hunt-to-case escalation path untested. |

---

### 11. TUI (`internal/tui/`)

| | |
|---|---|
| **Rating** | 4/10 |
| **Tests** | ❌ No tests |
| **Races** | ❌ Unknown |
| **Strength** | Rich terminal UI with bubbletea. Dashboard, investigations, SIEM, cases, config screens. |
| **Weakness** | **No tests at all.** TUI is notoriously hard to test but critical for user experience. No golden file tests for screen rendering. No integration test with backend. |

---

### 12. Edge Sync (`internal/edge/`)

| | |
|---|---|
| **Rating** | 4/10 |
| **Tests** | ❌ No tests |
| **Races** | ❌ Unknown |
| **Strength** | gRPC sync client for multi-node topology. Investigation sync across nodes. |
| **Weakness** | **No tests at all.** Network sync is fragile without tests. No retry logic tests. No conflict resolution tests. |

---

### 13. Plugin System (`internal/plugin/`, `internal/plugins/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Plugin (6 tests), Exporter (6 tests), SCA has tests |
| **Races** | ✅ Zero |
| **Strength** | Sidecar plugin loader (Python, binary). SCA CIS benchmark engine with 64+ policies. HTML report exporter with HTTP tests. |
| **Weakness** | Plugin loader tested at registry level only (no sidecar test). Exporter tests found and fixed a real slice-bounds bug. SCA policies are static. |

---

### 14. Agent Interface (`internal/agent/`)

| | |
|---|---|
| **Rating** | 6/10 |
| **Tests** | ✅ 3 tests (Agent interface, Input map, Capability struct) |
| **Strength** | Clean interface-based plugin system. Input/Output as map for flexibility. |
| **Weakness** | No tests for agent chaining or composition. No test for Output error handling. |

### 15. Locale / i18n (`internal/locale/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Has tests |
| **Strength** | English + Myanmar locale. Clean key-value lookup API. |
| **Weakness** | Only 2 locales. No RTL support. No pluralization rules. Not wired into all CLI output. |

---

### 15. Config (`internal/config/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Has tests |
| **Strength** | JSON config with auto-create. TSE config sub-commands. Notifier config. Defaults for everything. |
| **Weakness** | No config validation (unknown keys are silently ignored). No env var overrides. No hot-reload. |

---

### 16. Investigation (`internal/investigation/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Has tests |
| **Strength** | Full investigation lifecycle. Timeline entries. Status tracking. Report generation. Prefix ID lookup. |
| **Weakness** | No performance test for prefix ID lookup (LIKE query). No test for concurrent investigation updates. |

---

### 17. Task Queue (`internal/taskqueue/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ Has tests |
| **Strength** | Generic task queue with worker pool. Context cancellation. Graceful shutdown. |
| **Weakness** | No persistence (in-memory only). No task priority. No retry with backoff. |

---

### 18. Telemetry (`internal/telemetry/`)

| | |
|---|---|
| **Rating** | 7/10 |
| **Tests** | ✅ 7 tests (send, disabled, empty URL, server error, counts, startup) |
| **Races** | ✅ Zero |
| **Strength** | Anonymous usage reporting. Configurable opt-out. 7 tests cover normal/error/edge cases. httptest-based send verification. |
| **Weakness** | Only tests the send path. No test for crash recovery if send panics. |

---

### 19. EDR Sub-packages (`internal/edr_agent/queue`, `service`, `transport`, `updater`)

| | |
|---|---|
| **Rating** | 5/10 |
| **Tests** | ✅ Queue (7 tests). Service, transport, updater still untested. |
| **Races** | ✅ Zero (queue only) |
| **Strength** | Queue for EDR events — 7 tests (new, push, pop, eviction, empty, multi, path). Windows service wrapper. mTLS transport. Auto-updater. |
| **Weakness** | 3 of 4 sub-packages still untested (service, transport, updater — Windows-specific or need network mocking). |

---

## Summary

| Area | Rating | Tested | Key Risk |
|------|--------|--------|----------|
| TSE Storage | **9/10** | ✅ 15/15 | No multi-node |
| SIEM | **7/10** | ✅ | No raw syslog decoder test |
| Playbook/Dispatch | **7/10** | ✅ | LLM calls fragile |
| Detection/SIFT | **7/10** | ✅ | Rootkit behavioral untested |
| Config | **7/10** | ✅ | No hot-reload |
| Investigation | **7/10** | ✅ | Prefix lookup perf |
| Locale | **7/10** | ✅ | Only 2 locales |
| Task Queue | **7/10** | ✅ | No persistence |
| CLI/Server | **6/10** | ❌ | Entire HTTP API untested |
| EDR Agent | **6/10** | ⚠️ | unsafe.Pointer warnings |
| Threat Intel | **6/10** | ⚠️ | 5 integrations untested |
| Cases | **5/10** | ❌ | SQL untested |
| Compliance | **5/10** | ❌ | Reports untested |
| Plugin System | **5/10** | ⚠️ | Plugin loader untested |
| Hunt | **4/10** | ❌ | Scheduler untested |
| TUI | **4/10** | ❌ | No golden file tests |
| Edge Sync | **4/10** | ❌ | Network sync untested |
| Telemetry | **3/10** | ❌ | Privacy-sensitive untested |
| EDR sub-packages | **3/10** | ❌ | 4 packages untested |

**System-wide: 45/56 packages tested (80%). Build passes with zero CGO. 5 vet warnings in EDR agent.**

The **TSE** is the most mature subsystem. The **CLI/server, cases, compliance, hunt, TUI, edge, telemetry, and EDR sub-packages** are the biggest testing gaps. If the server goes down, there's no test to catch it. If case SQL has a bug, there's no test to catch it.
