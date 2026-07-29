# Trace Storage Engine (TSE) — Architecture & Implementation Plan

## The Problem

SQLite is the only storage engine. It's row-oriented OLTP. At scale, it hits three walls:

| Limit | Symptom | Threshold |
|-------|---------|-----------|
| **Write throughput** | Single-writer WAL lock. 10K batched inserts/sec ≈ ceiling. | ~50K events/sec |
| **Storage bloat** | Row format + JSON blobs = no compression. 1KB/event × 1B events = 1TB. | ~100M events before pain |
| **Time-range queries** | No partitioning. Full table scans on `edr_events`. | ~100M rows = multi-second |

## Architecture (4-Peer-Reviewed)

Four independent reviews converged on the same shape: **SQLite as durable WAL, Parquet as canonical store, manifest as single source of truth for what has safely moved from one to the other.**

The critical insight from the final review: **You're not avoiding the LSM architecture. You're renting its hardest parts from boring, battle-tested components.** SQLite is the memtable+WAL, the flusher is the memtable flush, compaction is LSM compaction, the manifest is the MANIFEST file. The design gets LSM semantics without writing an LSM from scratch.

```mermaid
flowchart TB
    subgraph Input[Ingest]
        C[Collectors / SIEM / Agents]
        IQ[Ingest Queue<br/>bounded, spill-to-disk]
    end
    subgraph Hot[Hot Tier - SQLite]
        BW[Batch Writer]
        WG[Dedicated Writer Goroutine]
        SQL[SQLite WAL]
        HT[Hourly Tables<br/>edr_events_2026072410+<br/>DROP TABLE retention]
    end
    subgraph Flush[Flush Pipeline]
        FL[Flusher<br/>reads: id > watermark]
        PQ[Parquet Segments<br/>events/{tenant}/{date}/{hh}/part-*.parquet]
        MAN[Manifest - SQLite<br/>SHA-256, atomic tx per file]
    end
    subgraph Cold[Cold Tier]
        QR[Query Router]
        HOTQ[hot: SQLite]
        COLDQ[cold: DuckDB]
        COMP[Compactor<br/>hourly → daily]
    end
    C --> IQ --> BW --> WG --> SQL
    SQL --> FL --> PQ --> MAN
    MAN -->|watermark| QR
    MAN --> COMP --> PQ
    QR --> HOTQ & COLDQ
    HOTQ & COLDQ --> MERGE[Merge + dedup by UUIDv7]
```

## What Changed From v4 (and Why)

| v4 | v5 (Final) | Reason |
|----|-----------|--------|
| Hot tier = single SQLite table, DELETE rows | Hot tier = hourly tables, DROP TABLE | DELETE billions of rows = WAL explosion, checkpoint stalls, vacuum. DROP TABLE = O(1), zero overhead. |
| N workers each write to SQLite | N workers feed a dedicated writer goroutine (owns SQLite connection) | Removes writer-lock contention entirely. One goroutine serializes batch INSERTs. |
| Indexes on agent, type, severity in hot tier | Single index: (ts_us) only | Every index is write-amplification tax on ingest ceiling. Rich indexing is Parquet's job (dictionary + min/max stats). |
| Events written as JSON blob in data column | 5-10 hottest JSON fields promoted to real columns (process_name, cmdline, parent_pid, sha256, dest_ip, src_ip, user, hostname) + residual as data_raw | Columnar decomposition of repetitive fields is where 10-20× compression comes from. ZSTD on opaque JSON = 3-5×. Predicate pushdown on real columns = fast queries. |
| Flusher accumulates flat | Flusher accumulates by (tenant_id, hour_of_timestamp) groups | Each group becomes a well-packed Parquet file sorted by (agent_id, ts_us). No cross-tenant mixing. |
| File write then manifest update | Temp path → fsync → atomic rename → manifest commit (single txn) | Atomic rename on POSIX. Crash before manifest commit = orphan GC'd on startup. Crash after = file committed. Exactly-once. |
| No orphan GC | Startup scan: delete files not in manifest or status='writing' | Prevents orphan accumulation from crashed flushes. |
| Timestamps as strings | INT64 epoch microseconds in Parquet | Min/max pruning on int64 is faster and smaller. |
| No audit trail | `ingested_at` stored alongside `ts_us` | Enables auditing clock skew and late event handling. |
| Offset-based pagination | Cursor-based pagination (UUIDv7 = free cursor) | Offset is quadratic under concurrent writes. UUIDv7 is simultaneously sort key, dedup key, and pagination token. |
| Single SQLite connection | Read-only connection pool for UI + dedicated writer goroutine | Checkpoint never pinned by long UI read. Passive checkpoint escalation to truncate only during idle. |
| No integrity scrub | Weekly re-hash of committed files → detect bit rot | Bit rot on year-old cold files that nobody reads until incident response. |
| DuckDB required for cold queries | Pure-Go fallback cold reader in default build | CGO-free build can read its own canonical data. DuckDB is performance upgrade, not requirement. |
| Watermark table | Singleton watermark: `CHECK (id = 1)` | Prevents accidental multi-row corruption. |

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **SQLite is the WAL** | All ingestion lands in SQLite. Single fsync per batch. ~1-2 hours of data. |
| **Hourly tables, DROP TABLE retention** | DELETE on billions of rows is disqualifying. DROP TABLE = O(1), no WAL explosion, no vacuum. |
| **Dedicated writer goroutine** | Owns the SQLite connection. N workers feed it over a channel. Removes writer-lock contention. |
| **Single index on hot table: ts_us** | Every extra index is write-amplification tax. Rich indexing is Parquet's job. |
| **Columnar-decomposed schema** | 5-10 hot JSON fields → real columns. This is where 10-20x compression comes from. |
| **Watermark-driven flusher** | Re-reads from SQLite (page cache = free). Atomic manifest commit per file. Exactly-once semantics. |
| **Manifest is single source of truth** | Not filesystem glob. Not wall clock. Router cutoff = watermark. No boundary race. |
| **Partition by {tenant}/{date}/{hour}** | NOT by agent. Agent is sort column. Parquet min/max + dictionary handles pruning. |
| **Pure-Go fallback reader in default build** | CGO-free build can read its own canonical data. DuckDB is optional performance upgrade. |
| **Weekly integrity scrub** | Re-hashes committed files. Detects bit rot before incident response. |

## Storage Tiers

### Hot: SQLite WAL (0-2 hours)

| Property | Value |
|----------|-------|
| Role | Write-ahead log + hot query tier |
| Schema | One table per hour: `edr_events_{yyyymmddhh}` |
| Index | `(ts_us)` only — single index for time-range queries |
| WAL mode | synchronous=NORMAL, passive checkpointing |
| Writer | Dedicated goroutine owns the connection |
| Readers | Pool of read-only connections (UI queries) |
| Retention | `DROP TABLE edr_events_{yyyymmddhh}` when fully behind watermark + safety window |
| Max rows | ~360M at 50K/s × 2h |

### Warm: Parquet (2 hours — 7 days)

| Property | Value |
|----------|-------|
| File format | Apache Parquet v2 |
| Compression | ZSTD level 1 (configurable via CompressionCodec enum) |
| Row group size | ~1M rows, 128MB |
| File target | 256MB uncompressed |
| Roll trigger | 256MB OR hour boundary |
| Partition | `events/{tenant}/{yyyy-mm-dd}/{hh}/part-NNNN.parquet` |
| Sorted by | (agent_id, ts_us) within each file |
| Timestamps | INT64 epoch microseconds |
| Schema | 5-10 hot JSON fields decomposed to real columns + data_raw BLOB for residual |
| Compaction | Hourly → daily files after 48h |

### Cold: Parquet (7 days+)

| Property | Value |
|----------|-------|
| Retention | TTL per compliance framework (PCI: 1y, HIPAA: 6y, default: 90d) |
| Deletion | Manifest status='expired' → grace period → delete files → status='deleted' |
| Integrity | Weekly scrub: re-hash committed files, detect bit rot |

## Columnar Schema

```sql
-- Events table (hot tier, one per hour)
CREATE TABLE edr_events_{yyyymmddhh} (
    id          TEXT PRIMARY KEY,   -- UUIDv7
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    ts_us       INTEGER NOT NULL,   -- epoch microseconds
    ingested_at INTEGER NOT NULL,   -- for lateness auditing

    -- Decomposed JSON fields (5-10 hottest)
    event_type  TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    process_name TEXT,
    cmdline     TEXT,
    parent_pid  INTEGER,
    sha256      TEXT,
    dest_ip     TEXT,
    src_ip      TEXT,
    user_name   TEXT,
    hostname    TEXT,

    -- Residual JSON payload
    data_raw    BLOB                -- zstd-compressed if >4KB
);
CREATE INDEX idx_{yyyymmddhh}_ts ON edr_events_{yyyymmddhh}(ts_us);
```

```sql
-- Manifest (separate DB)
CREATE TABLE parquet_files (
    file_id           TEXT PRIMARY KEY,
    path              TEXT NOT NULL UNIQUE,
    tenant_id         TEXT NOT NULL,
    level             INTEGER NOT NULL DEFAULT 0,  -- 0=hourly, 1=daily
    min_ts_us         INTEGER NOT NULL,
    max_ts_us         INTEGER NOT NULL,
    min_event_id      TEXT NOT NULL,
    max_event_id      TEXT NOT NULL,
    row_count         INTEGER NOT NULL,
    compressed_size   INTEGER NOT NULL,
    uncompressed_size INTEGER NOT NULL,
    sha256            TEXT NOT NULL,
    compression       TEXT NOT NULL DEFAULT 'zstd',
    schema_version    INTEGER NOT NULL DEFAULT 1,
    status            TEXT NOT NULL DEFAULT 'writing',
    -- writing | committed | superseded | expired | corrupted | deleted
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX idx_pf_lookup ON parquet_files(tenant_id, status, min_ts_us, max_ts_us);

CREATE TABLE watermark (
    id       INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    last_id  TEXT NOT NULL,
    last_ts  INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Registry of live hourly tables
CREATE TABLE hot_tables (
    table_name TEXT PRIMARY KEY,
    hour_start INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active'  -- active | flushed | dropped
);
```

## Queue Backpressure

```go
type IngestQueue struct {
    ch      chan *Event        // cap: 65536 (≥1s at 50K/s)
    spill   *DiskSpill         // segment files
    dropped atomic.Uint64
}

func (q *IngestQueue) Enqueue(e *Event) error {
    select {
    case q.ch <- e:
        return nil
    case <-time.After(q.enqueueTimeout):  // default 100ms
        if err := q.spill.Write(e); err != nil {
            q.dropped.Add(1)
            return ErrEventDropped
        }
        return nil
    }
}
```

Policy: block briefly → spill to disk → drop with counter + alert. Never silent. A SIEM that loses the events documenting the attack that overloaded it has failed at its one job.

## Flusher (Exactly-Once Semantics)

```go
func (f *Flusher) Run(ctx context.Context) {
    for {
        // 1. Read watermark (singleton, CHECK id=1)
        wm := f.manifest.GetWatermark()

        // 2. Read from hot tables: id > watermark
        rows := f.sqlite.Query(ctx, Query{MinID: wm.LastID, Limit: 100000})

        // 3. Accumulate by (tenant_id, hour_of_ts)
        groups := groupBy(rows, func(e *Event) GroupKey {
            return GroupKey{Tenant: e.TenantID, Hour: truncateHour(e.TsUs)}
        })

        // 4. For each group that's ready (≥256MB OR hour boundary):
        for _, g := range groups.ready() {
            sort.Slice(g, byAgentIDThenTsUs)
            tempPath := f.writeTempParquet(g)  // fsync file AND directory
            sha256, stats := f.checksum(tempPath)
            finalPath := f.rename(tempPath)    // atomic on POSIX

            // 5. One manifest transaction:
            f.manifest.Transaction(func(tx) {
                tx.InsertParquetFile(finalPath, stats, status='committed')
                tx.UpdateWatermark(stats.MaxID, stats.MaxTs)
            })
        }

        // 6. Cleanup flushed hot tables (safely behind watermark + margin)
        f.manifest.DropFlushedTables(wm.LastID)

        select {
        case <-ctx.Done(): return
        case <-time.After(f.interval):
        }
    }
}
```

**Crash safety matrix:**

| Crash point | Effect | Recovery |
|-------------|--------|----------|
| Before manifest commit | Watermark not advanced | Flusher re-reads same rows. Temp file GC'd on startup. |
| After manifest commit | Watermark advanced | Rows never re-flushed. File durable. |
| During manifest commit | Transaction rollback | Watermark unchanged. Same as crash before commit. |
| During SQLite batch write | Transaction rollback | Collector retries. ON CONFLICT DO NOTHING. |

## Query Router

```go
func (r *Router) Query(ctx context.Context, q Query) (*Result, error) {
    wm := r.manifest.Watermark()
    boundary := wm.Timestamp
    overlap := 10 * time.Minute  // covers flush latency + clock skew

    var res Result
    var wg errgroup.Group

    // Hot side (SQLite): data newer than watermark - overlap
    if q.Overlaps(boundary.Add(-overlap), time.Now()) {
        wg.Go(func() error {
            events, err := r.hot.Query(gctx, q.ClampSince(boundary.Add(-overlap)))
            if err != nil {
                res.AddWarning("hot tier: %v", err)
                return nil  // partial results, not failure
            }
            res.AppendHot(events)
            return nil
        })
    }

    // Cold side (Parquet via DuckDB or pure-Go): data older than watermark + overlap
    if q.Overlaps(time.Time{}, boundary.Add(overlap)) {
        wg.Go(func() error {
            files := r.manifest.FilesFor(q.TenantID, q.Since, q.Until)  // committed only
            events, err := r.cold.QueryFiles(gctx, files, q.ClampUntil(boundary.Add(overlap)))
            if err != nil {
                res.AddWarning("cold tier: %v", err)
                return nil
            }
            res.AppendCold(events)
            return nil
        })
    }

    wg.Wait()
    res.MergeSortDedupByID()  // UUIDv7: dedup = ID equality, sort = ID order
    res.ApplyLimitOffset(q)
    return &res, nil
}
```

**Partial-result transparency:** The UI can render "cold storage unavailable — showing last 2 hours only." This is the difference between a degraded SIEM and a lying one.

## Pagination (Cursor-Based)

```go
type Query struct {
    TenantID    string
    AgentIDs    []string
    EventTypes  []string
    MinSeverity int
    Since, Until *time.Time
    Limit       int
    Cursor      string   // last UUIDv7 seen; strictly-greater continuation
}
```

UUIDv7 makes the cursor free: it's simultaneously the sort key, the dedup key, and the pagination token.

## Fallback Reader (CGO-Free Default Build)

The default build includes a pure-Go Parquet reader that can evaluate simple `field = value` AND `ts BETWEEN` predicates with row-group pruning. Slower than DuckDB, but the default build can read its own canonical data.

```go
// default build — no CGO required
func (r *ParquetReader) Query(ctx context.Context, files []FileInfo, q Query) ([]*Event, error) {
    for _, f := range files {
        reader, _ := parquet.Open(f.Path)
        for _, rg := range reader.RowGroups() {
            if !rg.MinMax("ts_us").Overlaps(q.Since, q.Until) {
                continue  // row group pruning
            }
            // Scan matching rows
        }
    }
}
```

## Compaction

```go
func (c *Compactor) Run(ctx context.Context) {
    for each (tenant, day) older than 48h with hourly files:
        1. Read all part files for the day
        2. Re-sort by (agent_id, ts_us)
        3. Write day.parquet to temp, fsync, checksum
        4. One manifest transaction:
             INSERT day file (status='committed')
             UPDATE hourly files SET status='superseded'
        5. GC: delete superseded files after 1h grace period
}
```

## Integrity Scrub (Weekly)

```go
func (s *Scrubber) Run(ctx context.Context) {
    // Low-priority weekly pass over committed files
    for _, file := range s.manifest.GetFilesToScrub() {
        actualSHA := sha256File(file.Path)
        if actualSHA != file.SHA256 {
            s.manifest.SetStatus(file.ID, "corrupted")
            alert("TSE: bit rot detected in %s", file.Path)
        }
    }
}
```

Bit rot on year-old cold files that nobody reads until the incident response is exactly the failure you want caught before the incident.

## DuckDB Dependency (Opt-In)

```go
//go:build duckdb
func (d *DuckDBAnalytics) QueryFiles(ctx context.Context, files []FileInfo, q Query) ([]*Event, error) {
    // Manifest-pruned file list — not a glob
    paths := make([]string, len(files))
    for i, f := range files { paths[i] = f.Path }
    db, _ := sql.Open("duckdb", "")
    rows, _ := db.QueryContext(ctx, `
        SELECT * FROM read_parquet(?)
        WHERE ts_us >= ? AND ts_us < ?
        AND severity >= ?
    `, strings.Join(paths, ","), q.SinceUs, q.UntilUs, q.MinSeverity)
    return scanEvents(rows)
}
```

## Implementation Phases

| Phase | Weeks | Deliverable |
|-------|-------|-------------|
| 1 | 1-2 | Hourly hot tables + registry, batch writer, dedicated writer goroutine, queue with backpressure/spill. Crash-injection harness skeleton. |
| 2 | 3-4 | Flusher + watermark + manifest + atomic commit protocol + startup orphan GC. Run harness continuously. |
| 3 | 5 | Router (watermark cutoff, overlap merge, cursor pagination, partial-result warnings). Pure-Go fallback cold reader. |
| 4 | 6 | DuckDB reader behind build tag, manifest-driven file lists. |
| 5 | 7-8 | Compactor, cold-tier GC/TTL, integrity scrub, snapshots, soak benchmark. |

## Benchmark Targets

| Metric | Target | Gate |
|--------|--------|------|
| Sustained ingest | 50K ev/s, 24h soak, NVMe | p99 enqueue < 50ms; zero drops |
| Flush lag | < 90s steady state | Alert threshold: 15 min |
| Hot query (1h, 1 agent) | < 50ms | |
| Cold query (30d, 1 tenant, sev>=5) | < 2s over ~1B rows | |
| Boundary query | Correct merge, zero missing, zero dupes | Test under crash injection |
| Compression | >= 10x on columnar-decomposed schema | Measured on real EDR payloads |
| Crash recovery | kill -9 at random points, 1000 iterations | Zero committed-data loss, zero committed duplicates |

The last row is the one that matters. Build the crash-injection harness in Phase 1, not as an afterthought — it's the executable proof that the watermark design delivers what simpler architectures cannot.

## Snapshots

```bash
# Quiesce flusher → snapshot manifest + hot tables + Parquet → resume
trace snapshot create --output trace-snapshot-2026-07-24.tar.zst
trace snapshot restore --input trace-snapshot-2026-07-24.tar.zst
```

## What This Architecture Is

- **An LSM tree, built from boring components.** SQLite = memtable+WAL. Flusher = memtable flush. Compactor = LSM compaction. Manifest = MANIFEST file. You're not avoiding the LSM architecture; you're renting its hardest parts from battle-tested components.
- **A storage engine, not a database integration.** Parquet is the canonical format. The query engine (DuckDB) is swappable. The manifest is the metadata catalog.
- **Single-node by design.** Multi-node is future work via Parquet on object storage + manifest federation.

## What It Is Not

- **Not a Lucene competitor.** SIEM queries are structured (field = value), not free-text.
- **Not a multi-node cluster.** Not yet. The Parquet + manifest design makes it possible.
- **Not replacing SQLite for operational data.** SQLite stays for alerts, investigations, config.

## Evolution Path

```
Today:    SQLite (all data)

Phase 1:  Hourly hot tables + batch writer + queue
Phase 2:  Flusher + watermark + manifest + Parquet
Phase 3:  Router + pure-Go cold reader
Phase 4:  DuckDB analytics (opt-in CGO)
Phase 5:  Compaction + TTL + scrub + snapshots

Enterprise:
  SQLite (per-node WAL) + Parquet on S3 + any query engine

Future (distributed):
  Every node runs TSE independently. Parquet on shared object store.
  Cross-node query via manifest federation + DuckDB federated scan.
```

No rewrites between stages. Each phase is additive.
