# Trace — Remediation Plan (from AUDIT.md)

> Source: `dev/yma/AUDIT.md` (737 lines, 2026-09-20). Code root `dev/`.
> Scope: fix all P0/Critical first, then unblock scale, then harden.
> Rule: modular monolith stays. No microservices. No new features until Phase 0 exits.
> Gate rule: do NOT enable multi-tenant / hostile-network / fleet-hostile deployment until Phase 0 exit criteria pass.

## Execution order at a glance

```text
Phase 0 Safety (P0, days) ──gate──> Phase 1 Foundation (P1, 2-3 wks)
  ──gate──> Phase 2 Core (P1-P2, 3-4 wks) ──> Phase 3 Scale (P2-P3, 3-4 wks)
  ──> Phase 4 Capabilities (P3, ongoing, one workflow at a time)
```

- P0 = RCE, tenant leak, evidence loss, split-brain, unsigned supply, dead audit.
- P1 = config, boundaries, registries, LLM validation, observability baseline, silent-error fixes.
- P2 = detection correctness, queue/lease/DLQ, query bounds, S3/leader safety.
- P3 = alert/case/correlation/evidence/reporting/asset-risk completeness.

## Cross-phase invariants (apply to every change)

1. `exec.Command(argv)` only. `sh -c` / `powershell -Command <string>` deleted except a single gated helper that rejects by default.
2. Every server mutation binds to auth ctx (`ctxKeyAgentID` / user / org). Body/query IDs are hints, never authority. Every ownership update carries `AND agent_id=?` / `AND org_id=?`.
3. Secrets: 0600 files, `*_FILE` env support, header-only keys, never logged. `config.json` Save path fixed in the same PR that touches any secret.
4. Audit `Write` on every auth/dispatch/revoke/case/user/approval transition. No new destructive path without an audit test.
5. At-least-once + idempotent sinks + gap detection. No new exactly-once claims without a kill-9 test.
6. Each workstream ships with: migration/backfill, regression test, rollback note, docs delta.

---

## Phase 0 — Safety (P0)

Goal: kill RCE chains, close spoof/IDOR/tenant-spoof, stop disclosure, make updates verifiable, make storage durable and lossless, make audit real, make containment safe.
Exit gate: 0.1-0.9 all merged, `go test ./...`, `go vet ./...`, new security tests green, kill-9 suite green, no `sh -c` with variable input left, dashboard unauth test fails-closed.

### 0.1 Argv-only response (SEC-11, AI-10/12/23, A2) — FIRST

Files: `internal/response/response.go:80-230`, `internal/edr_agent/response/executor.go:50-72,209-407`, new `internal/response/executil.go` (shared).

- Create `executil` with argv constructors: `IptablesBlock(ip netip.Addr)`, `NetshBlock`, `PfctlBlock`, `MoveFile(src,dst)` (Go `os.Rename`, no shell), `KillPID(int)`, `Taskkill validated`, `Systemctl validated`, `Sc validated`.
- Validators: `netip.ParseAddr` + CIDR allowlist config; PID digits-only + `/proc` existence check; service name allowlist `^[A-Za-z0-9._-]{1,64}$`; paths confined under quarantine root via `filepath.Rel` + `O_NOFOLLOW`, reject `..`, devices, symlinks.
- `run_script`: deny-by-default. Gate behind `response.run_script_enabled=false` + signed policy file + per-execution approval token (0.9). Log attempt when denied.
- Delete client-side `chain` (`executor.go:50-72`): server expands chains into individually authorized actions, or reject `chain` with error.
- `rollback_command`: stop executing stored strings. Store structured `{action, argv, inverse}`; rollback builds argv from inverse. Migration: old string rows marked `legacy_unexecutable`.
- Verification: unit tests for validator bypass attempts (`;`, `&&`, `$()`, backticks, newline, `../`, symlink); `grep -rn 'sh -c' internal/response internal/edr_agent/response` returns only the gated helper; `go test ./internal/response/... ./internal/edr_agent/response/...`.
- Effort: M. Risk: breaks `run_script` workflows — flag + migration notes + compat window.

### 0.2 EDR trust boundary (SEC-02/04/06/08, AI-16-18, A13)

Files: `internal/server/sync.go:143-157,344-400,376-672,833-870,1155-1275`, `internal/server/permissions.go`, `internal/server/pb.go`, `internal/edr_agent/agent.go`.

- Auth on `/api/v1/edr/register`, `/update/download`, `/vuln/feed`. Enrollment: provision-token (admin-issued, single-use, expiry) or admin approval queue. Remove auto-mint on anonymous POST.
- Server-assigned `org_id`. Drop client `OrgID` from insert; derive from provision token / auth ctx.
- Ctx-bound IDs: overwrite body `agent_id` with `ctxKeyAgentID` in heartbeat/events/pending/result; `UPDATE/SELECT ... AND agent_id=?`; pending queue keyed by ctx, not `?agent_id=`.
- Permissions: DELETE agent requires `PermAgentRevoke`; compliance snapshot requires compliance perm + framework allowlist + score-range check; dispatch requires allowlist + schema + size cap (see 0.9 approval); enforce `ScopeFull/ReadOnly` method matrix.
- Validation: `action_type` enum allowlist; param JSON-schema per type; max body events (e.g. 1000 → 413); `AlertID` length guard (fix `[:8]` panic `sync.go:611`); `search` length cap; role against Role set.
- Verification: new `server_test.go` matrix — agent-A token + B id = 403/empty; heartbeat spoof rejected; cross-agent result = 0 rows; viewer DELETE = 403; read-only POST = 403; unauth register/download = 401. `go test ./internal/server/...`.
- Effort: M. Risk: open-fleet workflows break — ship migration token + compat window + docs.

### 0.3 Close disclosure + honest health (SEC-01/15)

Files: `internal/server/dashboard.go:39-47`, `internal/server/sync.go:876-940`, `internal/server/server.go:24`, `internal/config/config.go`.

- Gate dashboard + `/api/live|tse|charts` + `/metrics` behind auth (or bind metrics to localhost with explicit flag). Remove same-port open control plane.
- `/readyz` checks DB + TSE + disk; `/healthz` stays liveness. DB-down → 503 test.
- Keys: hash user keys (SHA-256 minimum, bcrypt/argon2id preferred for human keys), header-only (`Authorization: Bearer`), stop `Printf` of keys (write-once file 0600), add expiry + rotation (`rotate-key` already exists — wire expiry column), server-side rate-limit + lockout.
- Fix `admin.go:32` Sprintf JSON → `json.Marshal`; `edr_cmd.go:179` raw concat → `url.Query().Set().Encode()`; `pb.go:345` `LIMIT %d` → placeholder/whitelist.
- Verification: unauth dashboard/API = 401; DB-down ready = 503; key-in-URL rejected/logged warning. Effort: L-M.

### 0.4 Fail-closed updater (SEC-03/10/20)

Files: `internal/server/sync.go:1163-1275`, `internal/edr_agent/updater/updater.go:82-103`, `deploy/install.sh`, `deploy/install.ps1`, `.github/workflows/release.yml`.

- Signature over (version + sha) with offline pubkey (cosign/sigstore). Empty hash = refuse. HTTPS-only base URL from config (no `r.Host` construction → host-header poison gone).
- Semver compare (not string `>`). Separator-safe containment: `filepath.Rel` + `O_NOFOLLOW`, reject `..`, refuse symlinks. `fsync` file + dir before rename; stage → verify → swap → rollback.
- Installers: authenticated download + checksum/signature verify before `chmod 755`; key file 0600, not world-readable append.
- Release: keep LDFLAGS version (fix `make cross` drop), publish sha256 + signature, pin `gh-release` SHA.
- Verification: MITM/empty-hash/downgrade tests; `TestVersionCompare` semver table; installer dry-run verify. Effort: M. Risk: key ceremony + staged rollout — keep manual install path.

### 0.5 Durability: NORMAL + checkpoint + hour-split + single-txn (R1/R2, A4-A6, D5, P-M1)

Files: `internal/storage/sqlite/hot_store.go:49-156,225`, `internal/storage/sqlite/checkpoint.go:17`.

- `synchronous=OFF` → `NORMAL` (minimum; `FULL` for manifest stays). Wire `NewCheckpointer` passive loop + idle TRUNCATE in production path (`tse_init.go`), not just tests. Add WAL-size metric + alert.
- Split `WriteBatch` by hour (not `events[0]` table). Single transaction with prepared statement per chunk; chunk only on driver var limit; rollback on error (remove recursive partial-commit).
- Disk check: keep `StoragePathFunc` gate; promote disk-full from log-only to enforce (see 3.x) after metrics land.
- Verification: kill-9 suite (`harness/crash_test.go`) green; straddle-hour test (batch spanning HH:59→HH:00 lands in two tables); before/after throughput note (expect dip vs OFF — record it). Effort: L.

### 0.6 Lifecycle machine: compactor + TTL + retention (D8-D11, A19, R12)

Files: `internal/storage/compactor/compactor.go:62-179`, `internal/storage/gc/*`, `internal/storage/manifest/manifest.go`, `internal/storage/snapshot/create.go:22`.

- Compactor: use `AddFileTx/UpdateFileStatusTx` inside `Transaction` (fix divergence). Schedule `CleanupSuperseded` on tick + metric for superseded age/count.
- TTL: expire only if `MaxTS < cutoff` (fix over-fire); single owner (merge `ttl.applyOnce` vs `GC.collectOnce`); half-open file test.
- Retention: wire flusher-never-drops gap — drop only behind watermark + `HotWindow`; metric + test. Manifest: add `schema_migrations` ordering (fix bare CREATEs).
- Snapshot: checkpoint + atomic copy of db+wal+shm + manifest verify; restore dry-run test.
- Verification: `go test ./internal/storage/compactor/... ./internal/storage/gc/... ./internal/storage/manifest/...`; crash-during-compact test; TTL half-open test. Effort: M. Risk: upgrade backfill run — schedule window.

### 0.7 Audit that works + secret hygiene (SEC-15/16/17, AI-20/21, A17)

Files: `internal/audit/logger.go:38-83`, `cmd/trace/root.go:466`, `internal/server/sync.go`, `internal/config/config.go:130`, `internal/server/agent_config.go:55`, `cmd/trace/genkey.go:80`, `internal/playbook/executor.go:116-168`.

- Persist audit key (file 0600 or KMS env, not `New(nil)` per proc). Include `Details` in HMAC input (both Write and Verify). Paged `Verify` (not full scan).
- Wire `Write` on: auth success/fail, dispatch queue, action result, dismiss, revoke, user create/rotate, case transitions, approval grant/deny, compliance snapshot. Add `GET /api/v1/audit` with actor/resource/time filters.
- Secrets: config + `agent_defaults.json` 0600 (dir 0700); `*_FILE` variants for all keys/tokens/webhooks; `genkey` `Chmod 0600`; stop logging full params/outputs/scripts (redact keys/tokens/webhooks/scripts; cap lengths).
- Verification: test asserts one audit row per destructive action; restart preserves verify; `grep -rn 'api_key' internal --include=*.go` shows no log paths. Effort: M. Risk: log volume — redact + sample large outputs.

### 0.8 Tenancy end-to-end (SEC-08, A1)

Files: `internal/server/sync.go:535-689`, `internal/server/pb.go:330`, `internal/db/db.go`, `cmd/trace/serve.go:143`, storage writers.

- `TenantID` from auth ctx everywhere (remove `default`). Delete `OR org_id=''` fail-open. Add org predicates to investigations/correlations/agents/events/cases/hunts/compliance; backfill + index (`org_id`, `tenant_id`).
- Ingest validation: validate-or-mint UUIDv7 (fix client-ID watermark break, D6); clamp severity/time; pin tenant from ctx.
- Auto-case: rate-limit per (rule,entity); fix `<nil>` IOC junk; reconcile 3 severity scales into one mapping table + test.
- Verification: per-tenant tests (A reads B = empty/403; legacy `''` rows invisible); `EXPLAIN QUERY PLAN` shows index use. Effort: M. Risk: migration backfill window + reindex lock — run offline or batched.

### 0.9 Approvals that bind (AI-19, AI-06/15, TD-01)

Files: `internal/playbook/executor.go:70-208,220-221`, `internal/playbook/interpolate.go:101-102`, `internal/investigation/investigation.go:123-129`, `cmd/trace/approval.go`, `dev/playbooks/*.yaml`, `internal/playbook/*.yaml`.

- Per-step tokens: `{nonce, investigation_id, step_index, action, params_hash, approver, expiry}`. `waitForApproval` binds to token, TTL + escalation + approver notify; kill infinite 500ms poll (bounded wait + timeout → deny-closed).
- Add `wait: analyst_approval` to every destructive playbook (block-ip, quarantine-file, kill-process, restart-service, edr-isolate/kill, run_script if ever enabled).
- Implement or delete: `PendingApprovals` listing (DB-backed) and `${investigation.*}` refs — no permanent-error stubs left.
- Fix `ListPendingApprovals` select/scan mismatch (6-col vs 7-col) in the same PR.
- Verification: approval-for-step-A does not unblock step-B (TOCTOU test); expired token denies; CLI queue visible. Effort: M. Risk: approval UX change — ship CLI queue + notifier ping together.

---

## Phase 1 — Foundation (P1)

Goal: one config, clean extension points, contained AI, observable baseline, no silent loss, no dead code.
Exit gate: `config check` + `dump --effective` green; registries cover LLM/EDR/TI/Notifier/Decoder; LLM contract tests green; request-ID tracing present; silent-`continue` paths fixed or ticketed; pagination + idempotency on all fleet lists/mutations.

### 1.1 Single config loader

Files: `internal/config/config.go`, `internal/edr_agent/config.go`, `internal/server/agent_config.go`, `cmd/trace/serve.go`, `cmd/trace/root.go`, both `SIEMConfig` types.

- Precedence `TRACE_* > flag > file > DB(remote) > default`, struct-tag env binding, `Validate()` ranges, `config check` + `config dump --effective`. Delete ad-hoc `os.Getenv` (`TRACE_SERVER_URL/API_KEY`, `ENTROPY_ZSCORE`, `KILLCHAIN_WINDOW`).
- Merge the two `SIEMConfig` types (central `cfg.SIEM` is dead today); flags become overrides of the single struct. Full `MergeRemote` schema + JSON schema for agent; single `ServerAddr`; single ldflags `Version`.
- Externalize B-literals: timeouts, intervals, thresholds, TTLs, channel sizes, dedup window, UDP cap, quarantine dir/timeout, S3/edge/telemetry/TLS validity, page/evict limits. Guardrails: `Validate()` + severity cross-map test + air-gap URLs in config.
- Compat: unknown keys warn (not silent ignore) + `config migrate`. Docs updated in the same PR.

### 1.2 Registries over switches

Files: `dispatch/host.go:460-588`, `integration/edr/edr.go:125-383`, `root.go:389-404`, `integration/{splunk,elastic,otx,abuseipdb,notifier}`, `siem/siem.go:88`, `archive/{cve,intel}.go`.

- `LLMProvider` (per-provider schema + budget caps + auto prompt version), `EDRProvider` strategy + factory (config-carried auth), shared `Connector` adapter (base/timeout/auth/TLS-verify), `Notifier` self-registering map, `RegisterDecoder(name,priority,fn)` + load-once, `IntelSource` (`Fetch/Normalize/Cache`) with fan-out + TTL memoize.
- Remove the 7 switch clusters. `root.go` constructs from config, no literals.

### 1.3 Contain the planner (AI-01-05)

Files: `internal/dispatch/host.go:114-452`, `internal/playbook/interpolate.go:51-109`, `executor.go:97-182`.

- JSON-schema-validate LLM playbook + params; allowlist playbooks/params per caller; taint-track `input/result/outputs` — untrusted outputs (VT vendors, OTX, web markdown, Splunk `_raw`, logs, file bytes) cannot flow into `ip/path/hostname/script/query/webhook` or report without sanitization; verify-before-cache (keep prompt-versioned key); redact logs.
- Interpolation fail-closed (missing → error, not `""`); richer `if` (`>=`, `contains`, CIDR) after fail-closed lands.
- Tests: prompt-injection table, bad-JSON/empty/retry/fallback HTTP-mock, cache-poison, interpolation-missing-denies.

### 1.4 Observability baseline

Files: `server/sync.go:71-75,534-552`, `playbook/executor.go:39-168`, `storage/metrics/metrics.go`, `cases/manager.go:159-224`, `compliance/report.go:154-405`.

- Request IDs end-to-end (middleware → ctx → logs/DB/TSE/events); slog JSON with level+component; check `WriteEvent` errors; fix `rows.Scan continue` and compliance/edge/admin silent errors (propagate + corrupt-count + bad-JSON tests).
- Metrics as counter types: `http_requests_total{route,code}`, auth failures, heartbeat age, `siem_alerts_total`, `edr_action_results`, queue wait, enqueue/write/flush/watermark/drop. Readiness probes DB+TSE+disk.
- Timeline: distinguish 500-not-configured vs 404-no-log; document fsync/rotation crash window (or add fsync).

### 1.5 API hardening + debt sweep

- Cursor pagination everywhere (`router/pagination.go` wired to HTTP; `?limit&cursor`, max enforced, page-2 continuity test). Idempotency-Key on dispatch/register (409 on duplicate, dedup double kill/isolate).
- Standard envelope `{data,error,code,request_id}`; freeze v1; per-route codes documented.
- Delete dead stubs/pacifiers (TD-01/03/04/09), `ToParquetCompression` shim (TD-02), fix `Timeline` traversal (SEC-09: `Base` + allowlist).
- AuthZ matrix tests (viewer→dispatch/dismiss/admin = 403; agent key on user route = 401/403; dashboard = 401) — closes the Critical testing gap.

---

## Phase 2 — Core Architecture (P1-P2)

Goal: detection keeps up, work executes once, storage queries bounded, HA honest.
Exit gate: SIEM burst test green; no double-claim/duplicate-hunt; dedup/corr self-tests green; hour-prune + tenant-index tests green; leader-fencing test green (single writer); S3 SigV4 against MinIO + AWS-shape mock.

- SIEM: precompile regex, immutable rule snapshot, worker pool, JSON fast-path, fsnotify, line-cap + truncation counter, conn limiter + read deadlines, per-(rule,entity) suppress (fix RuleID-only bleed), evil-regex/ReDoS + malformed-YAML fuzz.
- Queues: task `UPDATE ... WHERE status='pending' ... RETURNING` + lease/attempts/DLQ; hunt `next_run` CAS + pool + cron lib (fix sequential 10m + N+1); batch bounded attempts → DLQ; agent drain loop preserving bytes/IDs (fix never-consumed `PopBatch`, delete-bad-rows, mint-IDs).
- Detection data: dedup table-name fix + full-batch persist + richer keys (start-time/cookie/inode/mtime) + correlate-pre-dedup; populate correlator `EventTypes` or match-all + self-test each rule fires; sift error contract (`(nil,err)` on scan failure, not `Output{error},nil`).
- Storage reads: hour-suffix prune, per-tier LIMIT pushdown, tenant predicate hot + cold row check (D3), persist `Annotations` (column or `DataRaw` envelope + migration + round-trip), composite indexes after write-bench, watermark/`FilesFor` TTL cache.
- Flush: deterministic FileID (tenant/hour/min-max), advance watermark only past contiguous ranges.
- S3/leader: SigV4 + streaming + `UseSSL=true` default + plaintext warning; fenced lease (epoch/term, CAS, watch loop with demotion, single writer).
- PG shim: quote-aware lexer or per-driver migrations + PG integration test (unblocks stateless-server plan).

---

## Phase 3 — Scalability (P2-P3)

Goal: bounded RAM, linear headroom, verifiable supply, enforced disks.
Exit gate: wide-query OOM test green (capped RAM); zero-drop soak green; backup restore drill green; disk-full enforced (not logged); images pinned + provenance; `go vet` hard gate (no `|| true`).

- Query: single k-way merge over cursors (replace materialize-then-limit), streaming row-group reads with early terminate, per-shard row caps, `ReaderPool` actually used by shard path.
- Write: single-txn prepared chunks; queue append-segments storing full events + drain + wired `OnDrop` (metrics + notifier); NACK/429 with `Retry-After`.
- Backup/disks: streaming backup (no whole-file `ReadFile`), filtered rotation (`tse-snapshot-*.tar.gz` only), disk-full enforce at 95% (warn 85%), WAL/truncate policy + metrics.
- Shards: global vector watermark or defer multi-shard until fenced single-shard saturates; document hash key; no N-change remap without backfill (consistent hash).
- Supply: signed plugin registry (checksum + cosign, pinned registry, explicit prompt), sandboxed sidecar (no stderr Discard, capability manifest deny-by-default), pinned digests (`:latest` removed), provenance/SBOM, CI `permissions:` minimal + SHA-pinned actions + hard vet + corpus-backed fuzz.
- Deploy: `.dockerignore` (`*.exe`, `.trace/`, logs, `config.json`, `intel/*.db`), `go mod verify` in image, `HEALTHCHECK`, fix `/root` vs `/home/trace` path bug, least-priv DaemonSet (drop `privileged`/hostPID/hostNetwork where possible, seccomp/AppArmor, real resources), external Secrets (remove `CHANGE_ME`/`tracetrace`), systemd `WorkingDir/EnvFile/LimitNOFILE`, TLS-by-default guidance.
- Rate limits: per-IP + per-key token buckets, event caps per POST, heartbeat storm throttle, 429 tests.

---

## Phase 4 — Advanced Capabilities (P3, one workflow at a time)

Goal: production SOC completeness without re-inheriting holes.
Prerequisite: Phases 0-2 exit gates green for the touched workflow.

- Alert lifecycle: status/owner/SLA, ack/assign/escalate, dedup-by-(rule,entity), single severity scale + mapping test (reconciles rules 0-5 / dashboard 7+/4-6 / autocase ≥4).
- Case state machine (`open→investigating→resolved→closed` + reopen clearing `closed_at`), scoped paginated `/api/v1/cases`, org predicates, evidence hash-chain + custody.
- Entity correlation graph (host/user/process/ip) + cross-rule joins + confidence decay (replaces IOC-count-only + 2-ID keys).
- Bounded approvals with visible queue + approver notify (builds on 0.9 tokens).
- Real audit query API + evidence-backed compliance (labels only after assessment linkage; no static-label assurance).
- Scheduled + multi-case + CSV/CEF reporting; `ColdTTL` verified end-to-end.
- Asset inventory + vuln join + risk scoring feeding triage.
- Versioned rule packs with hot-reload: `siem/rules/*.yaml`, `correlator.rules.yaml`, `seed-iocs.json` (deletes `sift/hash.go` dup), `yara/*.yar`, `scoring.weights.yaml`, `response/policy.yaml`, compliance packs. Kill substring FP (exact + CIDR), single `pe.entropy_threshold`, feed-backed CVE rows with expiry.

---

## Verification matrix (run per phase)

```text
go build ./... && go vet ./... && go test ./... -count=1
go test ./... -short -count=1 -p 2                      # fast path
go test -race ./internal/storage/... -short -timeout 300s
go test -tags cgo ./internal/storage/cold -timeout 120s  # DuckDB path
go test ./internal/server/... -run 'Auth|Scope|IDOR|Revoke|Compliance' -v
go test ./internal/storage/... -run 'TTL|Compact|Retention|Watermark|Straddle' -v
go test ./cmd/trace-agent/... -tags=integration          # after 0.2 registrar fix
bash deploy/e2e-test.sh && bash deploy/crash-test.sh     # 0.5/0.6 gate
bash deploy/malware-test.sh                              # detection gate
bash deploy/stress-test.sh && bash deploy/soak-test.sh   # Phase 2/3 gate
grep -rn 'sh -c' internal/response internal/edr_agent/response  # 0.1 gate: only gated helper
grep -rn 'OR org_id' internal/                           # 0.8 gate: zero hits
```

New tests each workstream must add (examples, not exhaustive): AuthZ 403 matrix; agent-A-vs-B IDOR trio (pending/heartbeat/result); validator bypass table (`;`, `$()`, backticks, newline, `../`, symlink); approval TOCTOU (token-A vs step-B); TTL half-open survives; compactor crash atomicity; straddle-hour partition; threshold-1 no-alert + window-slide + suppress-expiry; dedup restart no-reflood; correlator each-rule-fires; pagination page-2 continuity; idempotent re-POST = single action; ready DB-down = 503.

## Risks and rollbacks (per phase, condensed)

- 0.1/0.9 break `run_script` and approval UX → flag-gate, migration notes, keep manual path one release.
- 0.2 breaks open-fleet onboarding → provision-token compat window, bulk-issue script, audit of rogue rows before tightening.
- 0.4 needs key ceremony (signing keys, pubkey distribution) → stage keys first, dual-publish (sha + sig) one release, then enforce.
- 0.5 throughput dip (`OFF`→`NORMAL`) → publish before/after numbers from the same harness, keep `FULL` for manifest only.
- 0.6/0.8 need backfill windows → run offline or batched, reindex concurrently where supported, snapshot before migrate.
- Phase 2 query/flush rewrites → feature-flag + shadow reads comparing old vs new counts before cutover.
- Phase 3 plugin signing → explicit user prompt on first unsigned load, then deny-by-default next release.

## What stays vs what changes (guardrails against over-redesign)

- Stays: single `trace` + `trace-agent` binaries; cobra CLI shape; playbook YAML shape; SQLite-hot / Parquet-manifest-cold + UUIDv7 theory; offline embedded intel; pure-Go default + DuckDB opt-in; TUI + dashboard presentation (behind auth).
- Changes: trust path (gateway, identity, tenancy, approvals, argv, signatures); durability path (NORMAL, lifecycle machine, drains, leases, deterministic flush); operability path (IDs, metrics, readiness, audit, pagination, idempotency); extension mechanism (registries + data-driven rules).
- Explicitly NOT proposed: microservices, service mesh, Kafka/Raft before fenced single-node saturates, Lucene free-text, multi-writer SQLite, CGO-mandatory builds.

## Mapping to AUDIT TOP 20 (traceability)

0.1→#1, 0.2→#2, 0.3→#3, 0.4→#4, 0.2/1.5→#5, 0.9→#6, 0.3→#7, 0.5→#8, 0.6→#9, 0.7→#10, 0.7→#11, 0.8→#12, Phase 1.3→#13, Phase 2→#14, Phase 2→#15, Phase 2/3→#16, Phase 1.1/1.2→#17, Phase 1.4→#18, Phase 3→#19, Phase 4→#20.
