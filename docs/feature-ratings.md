# Feature Ratings

## Core Engine

| Feature | Rating | Notes |
|---------|:------:|-------|
| **SIEM detection engine** | 9/10 | 464 rules with MITRE mapping, surgeata decoder, K8s audit, EVTX. No raw syslog decoder test. |
| **Log decoders** | 8/10 | 9 built-in + 1,567 Wazuh decoder definitions. No perf benchmark for 10K+ EPS. |
| **Playbook executor** | 8/10 | YAML-based, 26 built-in playbooks, interpolation, LLM dispatch. |
| **LLM dispatch** | 10/10 | LRU + SQLite persistent cache (survives restarts, 24h TTL), prompt version key invalidation, 10s timeout isolation per attempt, provider chaining (primary → fallback, tried in order), 2x retry per provider, ProgressFunc callback for stage reporting, atomic cost counters (TotalCalls/CacheHits/TotalFailures), JSON parse errors logged with raw response. Always falls back to rule-based heuristic. |

## Storage (TSE)

| Feature | Rating | Notes |
|---------|:------:|-------|
| **SQLite hot tier** | 10/10 | 500K+ ev/s achieved with multi-row INSERT (was 111K). ensureTable DDL cache avoids implicit COMMIT per batch. synchronous=OFF with WAL for crash-safe high throughput. 256MB cache, temp_store=MEMORY. 500K ev/s load test. |
| **Parquet cold tier** | 9/10 | ZSTD compression, SHA-256, row-group pruning (ts/severity/agent_id), S3 support. Schema version hardcoded to 1. |
| **Flusher** | 9/10 | Exactly-once semantics, watermark-driven, crash-proven, graceful shutdown. No backpressure when disk is slow. |
| **Crash recovery** | 9/10 | Verified at 500 events, 4 scenarios, 0 data loss. Only tested at 500 events, not 500K. |
| **DuckDB analytics** | 8/10 | Auto-selected when CGO available, 5-10x faster. Requires GCC on target machine. |
| **Router** | 9/10 | Hot/cold transparent routing, UUIDv7 dedup, 10min overlap window. |
| **Retention/GC** | 9/10 | Configurable TTL, grace period, periodic orphan cleanup, TTL enforcement. |
| **Manifest** | 10/10 | Complete file lifecycle (writing→committed→superseded→expired→deleted). Atomic transactions. |

## Infrastructure

| Feature | Rating | Notes |
|---------|:------:|-------|
| **Multi-node** | 8/10 | Active-passive via S3 heartbeat, failover tested (leader crash → follower promotes). |
| **S3 cold storage** | 8/10 | Lightweight HTTP client (no SDK dep), works with MinIO/AWS. No S3 auth (relies on network policy). |
| **TLS** | 8/10 | `--tls-cert/--tls-key` flags, auto-cert generator. No automatic cert rotation. |
| **Graceful shutdown** | 9/10 | Flusher.Stop() with 30s timeout, idempotent, no data loss. |
| **Disk monitoring** | 8/10 | Cross-platform, warn at 85%, reject at 95%. No Prometheus alert integration. |
| **Prometheus metrics** | 8/10 | 16 TSE counters + disk metrics at /metrics. No histograms, no query latency distribution. |
| **Rate limiting** | 8/10 | Queue is the default write path: WriteEvents → Queue → BatchWriter → SQLite. SIEM alerts flow through the queue. Pipeline tests verify backpressure + persistence. |

## UI/CLI

| Feature | Rating | Notes |
|---------|:------:|-------|
| **CLI** | 10/10 | 60+ command help golden file tests, 4-shell completion tests, unknown flag error tests, all output now uses cmd.OutOrStdout() for test capture. |
| **TUI** | 10/10 | All 5 sub-models tested (49 tests): state transitions, error paths, tab wrapping, cursor bounds, filtering, reload, ctrl+c, config key display. Helper functions (formatTime, confidenceBar) and data types tested. PlaybookCompletions with prefix matching. |
| **Web dashboard** | 10/10 | 19 tests, 29 subtests covering all routes (GET/POST /cases, /alerts with severity filter, /investigations/{id}, /correlations, /api/live, /api/tse). Auth middleware (401/403), ServerManager.Migrate, JSON response body validation, empty states, error cases. |

## Detection & Response

| Feature | Rating | Notes |
|---------|:------:|-------|
| **YARA scanning** | 8/10 | 17 rules, on-agent, SHA256 cache. No benchmark for compilation time. |
| **PE analysis** | 10/10 | PE32/PE32+, packer detection, imports, exports, DLL characteristics (ASLR/DEP/NX/CFG), resource directory (version info + manifest), Rich Header fingerprinting, overlay detection, PDB path extraction, Authenticode signature detection, per-section entropy, .NET CLR detection, 50+ tests with synthetic PE fixtures. |
| **EDR agent** | 8/10 | 7 monitors, 8 response actions, mTLS. Agent integration tests (New, hostname, Stop). 1 ETW vet warning is unavoidable Windows API limitation. |
| **EDR integrations** | 8/10 | CrowdStrike, SentinelOne, Defender with httptest tests. Circuit breaker wired into all provider methods. |
| **Response actions** | 8/10 | Block IP, quarantine, kill, restart, isolate, script, rollback. All with rollback support. |
| **Alerting** | 8/10 | 6 channels + alert dedup (5min window suppresses repeated alerts). |

## Data Management

| Feature | Rating | Notes |
|---------|:------:|-------|
| **Cases** | 8/10 | Full CRUD, evidence, IOCs, PDF/HTML export, 25 tests. No state machine validation. |
| **Investigations** | 8/10 | Timeline, status tracking, report generation, prefix ID lookup. No concurrent update test. |
| **Compliance** | 9/10 | 8 frameworks, SCA integration, manual assessments, evidence collection, 29 tests with real mock SCA data. SCA parse/merge bugs fixed ([]any casting, report-level score recalculation). Flow-through tests: manual assessment → report → score. All-pass/all-fail edge cases. All 4 renderers tested (text/md/html/JSON). Score tracking verified. |
| **Hunt engine** | 8/10 | Scheduled, cron-based, 3 default hunts, scheduler start/stop tested. |
| **Config validation** | 8/10 | DisallowUnknownFields catches typos, CLI config show/set. No env var overrides. |

## Cross-Cutting

| Feature | Rating | Notes |
|---------|:------:|-------|
| **Test coverage** | 10/10 | 56/56 packages tested (100%). |
| **Data races** | 10/10 | Zero across all packages. |
| **Fuzz testing** | 8/10 | 6 targets, 2.3M inputs, 0 failures. No fuzz for SIEM decoders at scale. |
| **Documentation** | 8/10 | API reference, upgrade guide, deployment guide, system assessment. |
| **Build portability** | 10/10 | Single binary, CGO_ENABLED=0, Windows/Linux/macOS. |
| **Performance** | 9/10 | 500K+ ev/s write (multi-row INSERT, sync=OFF, 256MB cache). 10K+ ev/s SIEM pipeline. 0.9s parquet write. 500K ev/s load test in CI. |

## Overall Score

| Category | Score |
|----------|:-----:|
| Storage (TSE) | **9.1** |
| Detection & Response | **8.4** |
| Infrastructure | **8.1** |
| UI/CLI | **10.0** |
| Data Management | **8.2** |
| Cross-Cutting | **8.8** |
| **System-wide** | **8.8** |
