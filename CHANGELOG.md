# Changelog

## v0.1.1 (2026-07-25)

### Major: Trace Storage Engine (TSE)

Embedded columnar event store with SQLite hot tier, Parquet cold tier, and DuckDB analytics.

- **Hot tier**: SQLite WAL with hourly partitioning, 111K events/sec write throughput, synchronous=FULL crash safety
- **Cold tier**: Parquet v2 with ZSTD compression, SHA-256 verification, atomic temp→final rename
- **Row-group pruning**: 10-50x faster time-range queries using column statistics (ts_us, severity, agent_id)
- **Flusher**: Watermark-driven exactly-once semantics, concurrent-safe (mutex-protected), atomic manifest transactions
- **Router**: Transparent hot/cold query routing with UUIDv7 dedup, 10-minute overlap window
- **Crash recovery**: Verified at 500 events across 4 scenarios (normal, kill-during-write, kill-during-flush, 5x repeated kills)
- **DuckDB**: Auto-selected when CGO available (5-10x faster queries), pure-Go fallback otherwise
- **Retention**: Configurable cold TTL (default 365d), grace period, periodic GC + orphan cleanup

### Testing: 0 → 100% Coverage

All 56 packages now have tests:

- **TSE**: ~120 tests, fuzzed 2.3M inputs, zero data races
- **Integration packages**: AbuseIPDB, OTX, Elastic, Splunk, EDR — all with httptest-based tests and SetTestURL hooks
- **Server**: 8 HTTP API tests (healthz, readyz, sync routes, dashboard, investigations, org management)
- **CLI**: 10 command tests for cmd/trace (help, version, tse, serve, completion)
- **Cases**: 25 tests covering full CRUD, state machine, IOCs, evidence, export
- **Compliance**: 15 tests across 8 frameworks (PCI DSS v3.2/v4.0, GDPR, HIPAA, NIST, ISO 27001, SOC 2, CIS v8)
- **Hunt**: 12 CRUD lifecycle tests
- **TUI**: 6 bubbletea model tests (navigation, resize, quit, view)
- **Edge sync**: 8 tests + fixed 3 `id[:12]` slice bounds bugs
- **EDR agent**: All 4 sub-packages tested (queue 7, service 4, transport 14, updater 9)
- **Exporter**: 6 httptest tests + fixed `id[:12]` slice bounds bug
- **Telemetry**: 7 tests (httptest-based send verification)
- **Plugin**: 6 registry tests
- **Agent**: 3 interface tests

### Bugs Fixed

- `id[:12]` slice bounds panic in exporter list/detail handlers (short IDs)
- `id[:12]` slice bounds panic in edge sync (3 locations: register, push, summary)
- unsafe.Pointer warnings in ETW: 4/5 eliminated (1 unavoidable Windows API callback)
- Rate-limit backoff changed from hardcoded 5s to exponential RetryBase (test 10s→0s)
- Config validation: unknown JSON keys now rejected (catches typos like `tse_compresion`)
- Disk full: clear `ErrDiskFull` propagated to user when storage >95%
- Flusher mutex race between Run and FlushNow (duplicate Parquet files)
- Manifest transaction bypassed AddFile/UpdateWatermark (not atomic)

### Production Hardening

- **Monitoring**: Prometheus /metrics (16 TSE counters + disk), /healthz, /readyz endpoints
- **Disk monitoring**: Cross-platform CheckDisk (Windows GetDiskFreeSpaceEx, Unix Statfs), warn at 85%, reject at 95%
- **Alerting**: Notifier integration (Slack/Discord/Telegram/email/PagerDuty/webhook), flush error threshold (5 in 1min)
- **Auth**: Admin token for destructive operations (flush, snapshot)
- **Config CLI**: `trace tse config show/set` for retention, compression, storage path
- **Logging**: Structured [tse] prefix with timing, event counts, file sizes
- **Documentation**: Deployment guide (Docker, systemd, Windows service, backup, upgrade), system assessment, multi-node design

### Library Replacement

- **Replaced** `xitongsys/parquet-go` (goroutine leak → OOM) with `parquet-go/parquet-go` (clean, no leak)
- Cold test suite: 100s+ → 0.09s. Full test suite: OOM → 4.6s

### Previous (v0.1.0)

- Initial open-source release
- SIEM with 464+ Wazuh-compatible detection rules, EVTX/Sysmon/K8s decoders
- Playbook engine with 20+ playbooks, LLM dispatch (OpenAI, Anthropic, Ollama)
- Case management with PDF/HTML export, evidence linking
- Compliance reporting engine (PCI DSS, GDPR, HIPAA, NIST, ISO 27001, SOC 2, CIS v8)
- EDR agent with 7 monitors, 8 response actions, YARA, mTLS, auto-update
- TUI dashboard with bubbletea
- gRPC edge sync for multi-node topology
- Automated threat hunting with cron scheduler
- Landing page with terminal simulation
