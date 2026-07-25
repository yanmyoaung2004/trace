# TSE Remaining Work

## Gap 1. Parquet Goroutine Leak (Production Risk)

**Problem:** `xitongsys/parquet-go` leaks goroutines on every `NewParquetReader` call. Each read spawns thousands of goroutines that never terminate. On repeated reads → OOM.

**Fix options (choose one):**

**Option A — Mitigate (2h):** Add a `ParquetReaderPool` that creates readers once and reuses them. Wrap `ParquetReader` with a sync.Pool. Caches file handles. Still leaks but doesn't grow unbounded in production.

**Option B — Replace library (2-3d):** Replace `xitongsys/parquet-go` with `github.com/parquet-go/parquet-go` (the Apache-licensed alternative). This requires:
  - Rewrite `internal/storage/parquet/writer.go` (schema, compression, write path)
  - Rewrite `internal/storage/cold/parquet_reader.go` (read path, filtering, row-group pruning)
  - Rewrite `internal/storage/parquet/schema.go` (TraceEventParquet struct tags)
  - Update all tests that write/read Parquet files
  - Run full benchmark comparison

**Option C — DuckDB for cold reads (1-2d):** Make DuckDB the default reader (currently behind `-tags duckdb`). Install DuckDB via CGO. Remove pure-Go fallback. Slower startup, faster queries, no goroutine leak.

| Option | Effort | Risk | Maintainability |
|--------|--------|------|-----------------|
| A (Pool) | 2h | Low (band-aid) | Medium |
| B (Replace) | 2-3d | High (rewrite) | High |
| C (DuckDB) | 1-2d | Medium (CGO) | High |

**Recommended:** Option A immediately (plug the leak). Option B within 2 weeks (permanent fix).

---

## Gap 2. DuckDB Tests

**Files:** `internal/storage/cold/duckdb.go`, `internal/storage/cold/duckdb_stub.go`

**What's needed:**
- Add DuckDB to CI (CGO toolchain)
- Write `internal/storage/cold/duckdb_test.go`:
  - `TestDuckDB_ReadsParquet` — write via `ParquetWriter`, read via DuckDB
  - `TestDuckDB_QueryEquivalence` — same query on DuckDB and pure-Go reader, compare results
  - `TestDuckDB_Performance` — benchmark showing 5-10x speedup over pure-Go
- Tag all with `//go:build duckdb`

**Blocks on:** Gap 1 (if migrating away from xitongsys, DuckDB tests change too)

---

## Gap 3. Fuzz Testing

**Targets:**
- `storage.MergeSortDedupByID` — fuzz with random event slices (dups, empty, large)
- `cold.clampQuery` — fuzz with random query parameters and bound values
- `sqlite.buildHotQuery` — fuzz with random table lists and queries
- `parquet.writer.WriteBatch` — fuzz with random events (edge case field values: unicode, very long strings, negative timestamps)

**Files to add:**
- `internal/storage/fuzz_test.go` (package storage)
- `internal/storage/cold/fuzz_test.go`
- `internal/storage/sqlite/fuzz_test.go`

**Effort:** 4h

---

## Gap 4. Crash-Injection Recovery Tests

**Files:** `internal/storage/harness/crash.go` (incomplete)

**What's missing:**
1. `VerifyDataIntegrity(dir string) (totalEvents int, violations []string, err error)` — currently returns `0, nil, nil`
2. Test binary that accepts `-data-dir` and `-crash-point` flags, runs write→flush operations, and injects crashes at defined points
3. Actual test in `harness/crash_test.go` that runs N iterations of: start binary → write events → kill → restart → verify no data loss/no duplicates

**Plan:**
1. Implement `VerifyDataIntegrity`:
   - Open SQLite hot store → count events
   - Open manifest → count watermark + parquet files
   - Read each Parquet file → verify event IDs are contiguous with watermark
   - Check no duplicates across hot + cold
2. Create test binary at `cmd/tse-crash-test/main.go`
3. Write `TestCrashRecovery` in harness

**Effort:** 1-2d

---

## Gap 5. Race Detection

**What to run:**
```
go test -race ./internal/storage/... -short -count=1 -timeout 300s
```

**Known risks:**
- `sqlite.SQLiteHotStore.liveTables` — uses `sync.Mutex` but Query reads it outside the lock (line 127: `s.mu.Lock()` / 130: `copy(tables, s.liveTables)`). Already properly locked.
- `metrics.Global` — accessed from multiple goroutines. All fields are `atomic.*` so this is safe.
- `flusher.Flusher` — Run goroutine vs FlushNow call. Need to verify no race on `f.hot` or `f.manifest`.
- Router concurrent goroutines for hot + cold queries (lines 62-81, 87-119). Uses `sync.WaitGroup` + `sync.Mutex`. Should be safe but needs verification.

**Effort:** 1h to run + fix any discovered races

---

## Gap 6. Load/Stress Tests

**Test to write (`internal/storage/harness/load_test.go`):**
```
TestPipeline_100kEventsThroughput:
  - Create hot store + manifest + flusher
  - Write 100,000 events in batches (1000 per batch)
  - Wait for all to flush (short flush interval)
  - Verify watermark = last event ID
  - Measure: total time, events/sec, flush latency
  - Target: >10,000 events/sec on consumer hardware
```

**Effort:** 4h

---

## Execution Order

| Priority | Gap | Effort | Why first |
|----------|-----|--------|-----------|
| P0 | Gap 1 (Mitigate) — Parquet leak | 2h | Production risk, blocks everything |
| P1 | Gap 5 — Race detection | 1h | Easy, finds real bugs |
| P2 | Gap 4 — Crash-injection | 1-2d | Verifies exactly-once semantics |
| P3 | Gap 3 — Fuzz testing | 4h | Finds edge-case panics |
| P4 | Gap 6 — Load tests | 4h | Proves throughput claims |
| P5 | Gap 1 (Replace) — New parquet lib | 2-3d | Permanent leak fix |
| P6 | Gap 2 — DuckDB tests | 1h | Requires Gap 1 resolve first |
