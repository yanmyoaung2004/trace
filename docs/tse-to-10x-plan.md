# TSE — 10x Production Readiness Plan

Push all 7 dimensions from current scores to 10/10.

Current scores: Correctness 9, Data Integrity 9, Performance 7, Crash Recovery 9, Monitoring 3, Flexibility 7, Production Readiness 6

---

## Phase A — Hardening (7h)

**Target:** Correctness 10, Data Integrity 10, Crash Recovery 10

### A1. SQLite synchronous=FULL (5min)
`sqlite/hot_store.go` + `manifest/manifest.go`
Change `PRAGMA synchronous=NORMAL` → `FULL`. Data is physically on disk after every write tx. ~2x write slowdown, worth it for crash safety.

### A2. Periodic orphan cleanup (1h)
`gc/gc.go`
Move `OrphanGC` from startup-only into the periodic GC loop. Cleans crashed `status=writing` parquet files within 24h max.

### A3. Memory limit on queries (4h)
`sqlite/hot_store.go` + `types.go`
Add `MaxMemory` to `Query`. Limit to 100K events per query. Prevents OOM from reading 10M events into RAM. Return partial results with warning.

### A4. Hot store row checksums (2h)
`sqlite/hot_store.go`
Add `sha256` column to hot tables. Compute on write, verify on read. Catches silent corruption.

---

## Phase B — Monitoring (10h)

**Target:** Monitoring 8→9

### B1. Prometheus /metrics endpoint (4h)
`metrics/metrics.go` + `cmd/trace/serve.go`
Register handler. Export all 16 counters as `trace_tse_*` gauges.

### B2. Disk space monitoring (2h)
`storage/storage.go` + `flusher/flusher.go`
Check `Statfs` before writes. Warn at 85%, reject at 95%. Export as `trace_tse_disk_bytes_*`.

### B3. Retention enforcement loop (4h)
`gc/gc.go` + `admin/commands.go`
Active loop marks files past TTL as `expired`. GC handles deletion. Add to `trace tse status` output.

---

## Phase C — Performance (10h)

**Target:** Performance 7→9

### C1. Row-group pruning (1d)
`cold/parquet_reader.go`
Read parquet metadata row-group statistics before reading rows. Skip non-matching groups using `Min()`/`Max()` on `ts_us` and `severity` columns. Expected: 10-50x faster time-range queries.

### C2. Compression config via CLI (2h)
`cmd/trace/tse_init.go` + `config/config.go`
Expose `--parquet-compression`, `--parquet-row-group-size`, `--parquet-compression-level`.

---

## Phase D — Production Hardening (8h)

**Target:** Production Readiness 6→9, Flexibility 7→10

### D1. Rate limiting / backpressure (4h)
`queue/queue.go` + `types.go`
Hard `MaxQueueDepth`. Return `ErrBackpressure` when full. Ring-buffer eviction of oldest events. Config: `max_queue_drop_ratio`.

### D2. Configurable retention via CLI (2h)
`cmd/trace/tse_cmd.go` + `admin/commands.go`
`trace tse config set retention.days 90`. Reads/writes `~/.trace/config.json` under `tse.*`.

### D3. Structured logging (2h)
All storage packages.
Replace `log.Printf` with `[tse]` prefixed lines with duration/count/size.

---

## Phase E — Final Polish (2d)

**Target:** All 10s

### E1. Alerting hooks (4h)
`notifier/notifier.go`
Alert when flush errors > 5/min, disk > 90%, queue > 80%. Reuse Slack/Discord/Telegram/email/PagerDuty.

### E2. Admin auth (2d)
`server/sync.go` + `server/pb.go`
Admin token in config. Required for destructive ops. Non-destructive stays open.

---

## Execution Order

| Phase | Tasks | Effort | Biggest gain |
|-------|-------|--------|-------------|
| **A** | 4 | 7h | Safety — foundation first |
| **B** | 3 | 10h | See what's happening |
| **C** | 2 | 10h | Speed |
| **D** | 3 | 8h | Ops usability |
| **E** | 2 | 2d | Alerts + auth |

**Total: ~55h, 14 tasks.**

## Score Progression

```
        C   I   P   R   M   F   PR
Before: 9   9   7   9   3   7   6
After:  10  10  9   10  9   10  10
```

Multi-node replication is the only 10 not reached — that's a separate Phase 1+ effort (weeks).
