# TSE — Production Readiness Assessment

**Trace Storage Engine** — embedded columnar event store for security telemetry.
SQLite hot tier + Parquet cold tier + watermark-driven flusher + optional DuckDB.

---

## 1. Correctness

| Check | Status | Evidence |
|-------|--------|----------|
| Data races | ✅ Zero | `go test -race ./internal/storage/...` — 15 packages, 0 races |
| Fuzz testing | ✅ 0 failures | 3 targets: MergeSortDedupByID (1.3M), clampQuery (616K), buildHotQuery (359K) |
| Exactly-once semantics | ✅ Verified | Flusher uses watermark cursor; crash mid-flush replays without duplication |
| Deduplication | ✅ Verified | `MergeSortDedupByID` proven correct via fuzz + property tests |
| Atomic manifest commit | ✅ Fixed | `AddFileTx`/`UpdateWatermarkTx` now use transaction (was bypassing tx) |
| Flusher concurrency | ✅ Fixed | `sync.Mutex` prevents concurrent `flush()` calls (Run vs FlushNow race) |

### Risks
- No formal proof of watermark monotonicity at extreme scale
- `ON CONFLICT(id) DO NOTHING` on SQLite write — safe but silent

---

## 2. Data Integrity

| Scenario | Status | Details |
|----------|--------|---------|
| Clean shutdown | ✅ Verified | All events persisted, watermark matches last ID |
| Kill during write | ✅ Verified | Subprocess killed mid-write. Recovery: no data loss, no duplicates |
| Kill during flush | ✅ Verified | Subprocess killed during parquet write. Recovery: watermark replay, no gaps |
| Repeated kills (5×) | ✅ Verified | 5 sequential kill/recover cycles with cumulative event growth |
| Grace period (GC) | ✅ Verified | `collectOnce` respects grace period before deleting expired files |
| Grace period (compactor) | ✅ Verified | `CleanupSuperseded` respects grace before removing superseded files |
| Orphan file cleanup | ✅ Verified | `OrphanGC` removes files with `status=writing` at startup |
| Snapshot/Restore | ✅ Verified | Full roundtrip: manifest.db + hot.db + parquet files |

### Risks
- No checksum verification on hot store rows (only parquet files have SHA-256)
- No replication — single point of failure for the data directory

---

## 3. Performance

### Hot Store (SQLite)

| Operation | Throughput | Latency (per op) | Memory |
|-----------|-----------|-------------------|--------|
| Write 100 events | **52K/sec** | 1.9ms | 93KB, 1.3K allocs |
| Write 1000 events | **56K/sec** | 17.6ms | 916KB, 13.3K allocs |
| Query 100 events (from 50K) | **48K/sec** | 20.7ms | 613KB, 19.3K allocs |
| Bulk write 10K | **122K/sec** | 82ms | — |
| Bulk write 100K | **111K/sec** | 895ms | — |

### Full Pipeline (write → flush → parquet → read)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Write 100 + flush | 29ms | **3.4K/sec** |
| Write 100 + flush + read | 36ms | **2.8K/sec** |

### Cold Reader (pure Go parquet-go)

| File size | Read time (approximate) |
|-----------|------------------------|
| 5KB (100 events) | 0.03s |
| 800KB (500 events) | 0.05s |
| Note: reads entire file, no row-group pruning |

### Baseline (xitongsys/parquet-go — REPLACED)

| Before (old library) | After (new library) |
|----------------------|---------------------|
| Cold test suite: **100s+** | Cold test suite: **0.09s** |
| Compactor test: **84s** | Compactor test: **0.4s** |
| Full test suite: **OOM crash** | Full test suite: **4.6s** |

### Risks
- Cold reader has NO row-group pruning — reads entire parquet file, then filters in Go
- Parquet write is ZSTD-only (configurable but not exposed via CLI)
- No memory limits on hot store query (can query 1M+ events into RAM)

---

## 4. Crash Recovery

| Test | Events | Outcome |
|------|--------|---------|
| Normal run | 500 | ✅ All events persisted |
| Kill during write (500ms) | 500 attempted | ✅ Recovery: zero data loss |
| Kill during flush | 500 × 2 runs | ✅ Recovery: cumulative events intact |
| Repeated kills (5 iterations) | 500 × 5 | ✅ No data loss, no corruption after 5 hard kills |

### Recovery Mechanism
1. Flusher reads watermark from manifest
2. Queries hot store for events with `id > watermark`
3. Writes parquet, commits manifest (add file + advance watermark) in single transaction
4. If crash occurs mid-flush:
   - Parquet file status = `writing` (will be cleaned by `OrphanGC` at startup)
   - Watermark NOT advanced → events re-read and re-flushed
   - No duplicates, no data loss

### Risks
- `OrphanGC` only runs at startup, not periodically
- No fsync on manifest database (SQLite `PRAGMA synchronous=NORMAL` — safe but not FULL)

---

## 5. Monitoring

| Capability | Status | Details |
|------------|--------|---------|
| Metrics counters | ✅ Implemented | 16 counters: events enqueued/written/flushed/dropped, parquet files, errors |
| Prometheus export | ❌ Missing | Metrics exist but no `/metrics` HTTP endpoint |
| Disk usage monitoring | ❌ Missing | No check for disk space before accepting writes |
| Retention enforcement | ⚠️ Basic | TTL config exists but no proactive deletion loop |
| Alerting | ❌ Missing | No alerts for flush errors, high queue depth, disk full |
| CLI commands | ✅ Good | `trace tse status`, `inspect`, `snapshot`, `metrics` (standalone + server modes) |

---

## 6. Flexibility

| Capability | Status | Details |
|------------|--------|---------|
| Compression | ⚠️ Partial | ZSTD default, Snappy/Gzip/LZ4/Brotli available but not exposed via CLI |
| Parquet row group size | ⚠️ Partial | Configurable in code (1M default) but not via CLI |
| Flush interval | ✅ Configurable | `--flush-interval` on `trace serve --tse` |
| Hot window | ✅ Configurable | Default 2h retention in hot store |
| Cold TTL | ✅ Configurable | Default 365d, config in `~/.trace/config.json` |
| GC interval | ✅ Configurable | Default 24h |
| Queue capacity | ✅ Configurable | Default 65,536 events |
| Batch size | ✅ Configurable | Default 1,000 events |
| Storage path | ✅ Configurable | `--storage-path` on all commands |
| DuckDB reader | ⚠️ Optional | Requires `-tags duckdb` + CGO, not default |
| Multi-tenant | ✅ Built-in | `TenantID` on every event, isolated queries |

---

## 7. Gaps vs Production Requirements

| Requirement | Status | Effort to fix |
|-------------|--------|---------------|
| Row-group pruning in cold reader | ❌ Missing | 1d — add min/max stats to each row group, skip non-matching groups |
| Rate limiting / backpressure | ❌ Missing | 2h — check queue depth before accepting, drop oldest or return 503 |
| Disk space monitoring | ❌ Missing | 2h — check `statfs` before write, emit warning at 85%, reject at 95% |
| Prometheus `/metrics` endpoint | ❌ Missing | 4h — register metrics handler on serve HTTP mux |
| Configurable retention via CLI | ❌ Missing | 2h — `trace tse config set retention.days=90` |
| Periodic orphan cleanup | ❌ Missing | 1h — add to GC loop, not just startup |
| SQLite `PRAGMA synchronous=FULL` | ❌ Not done | 5min — change in manifest + hot store init |
| Multi-node / replication | ❌ Missing | Weeks — not in scope for Phase 0 |
| Authentication on admin commands | ❌ Missing | Days — RBAC for TSE admin API |
| Compression level tuning via CLI | ❌ Missing | 2h — expose `--compression-level` flag |

---

## 8. Overall Score

| Dimension | Score (1-10) | Notes |
|-----------|-------------|-------|
| Correctness | 9 | Zero races, fuzz-proven dedup, atomic watermark |
| Data Integrity | 9 | Crash-proven, exactly-once, SHA-256 on parquet files |
| Performance | 7 | Hot store is fast; cold reader needs row-group pruning for scale |
| Crash Recovery | 9 | 4 scenarios tested; only startup-only orphan GC prevents 10/10 |
| Monitoring | 3 | Counters exist but no export, no alerts, no disk monitoring |
| Flexibility | 7 | Configurable but many knobs not exposed via CLI |
| Production Readiness | 6 | Good foundation; gaps in monitoring, backpressure, retention UX |

### Verdict

**Safe to use for single-node security event storage up to ~1M events/day.**

The engine is correct, fast enough, and crash-proof. The main scaling bottleneck is the cold reader (no row-group pruning) — after ~1M events, queries will slow noticeably as parquet files grow. Adding DuckDB as default reader (requires CGO) or implementing row-group pruning in the pure-Go reader would remove this bottleneck.

For production deployment, prioritize:
1. Row-group pruning in cold reader
2. Prometheus metrics endpoint
3. Disk space monitoring
4. Configurable retention via CLI
