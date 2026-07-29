# Trace Storage Engine (TSE) — Final Architecture

**Version:** 5.0  
**Status:** Endorsed by 4 independent peer reviews  
**Design principle:** SQLite is the durable WAL. Parquet is the canonical store. The manifest is the single source of truth for what has safely moved between them.

---

## One-Sentence Architecture

SQLite is the write-ahead log. A watermark-driven flusher re-reads from SQLite (page cache = nearly free I/O) and writes columnar-decomposed Parquet files. The manifest tracks every file with SHA-256 checksums. DuckDB reads Parquet. Retention is `DROP TABLE` on hourly SQLite tables behind the watermark.

---

## Architecture Diagram

```mermaid
flowchart TB
    subgraph Input[Ingest]
        C[Collectors / SIEM / Agents]
        IQ[Ingest Queue<br/>bounded, spill-to-disk]
    end
    subgraph Hot[Hot Tier - SQLite]
        BW[Batch Writer]
        WG[Dedicated Writer<br/>Goroutine]
        SQL[SQLite WAL]
        HT[Hourly Tables<br/>edr_events_2026072410<br/>edr_events_2026072411<br/>...<br/>DROP TABLE for retention]
    end
    subgraph Flush[Flush Pipeline]
        FL[Flusher<br/>reads: id > watermark]
        PQ[Parquet Segments<br/>events/{tenant}/{date}/{hh}/part-*.parquet]
        MAN[Manifest - SQLite<br/>separate DB, SHA-256]
    end
    subgraph Cold[Cold Tier - Query]
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

---

## Storage Tiers

### Hot: SQLite WAL (0–2 hours)

| Property | Value |
|----------|-------|
| Role | Write-ahead log + hot query tier |
| Schema | One table per hour: `edr_events_{yyyymmddhh}` |
| Index | `(ts_us)` only |
| WAL mode | synchronous=NORMAL, passive checkpointing |
| Writer | Dedicated goroutine owns the SQLite connection |
| Readers | Pool of read-only connections for UI queries |
| Retention | `DROP TABLE` when behind watermark + safety window |

**Why hourly tables instead of DELETE:** DELETE on billions of rows causes WAL explosion, checkpoint stalls, and vacuum overhead. DROP TABLE is O(1) — zero I/O, instant.

**Why a dedicated writer goroutine:** Removes SQLite writer-lock contention entirely. N ingest workers feed batches to it over a channel.

**Why only one index:** Every extra index is a write-amplification tax on your ingest ceiling. Rich indexing (dictionary encoding + min/max stats) is Parquet's job, not SQLite's.

### Warm: Parquet (2 hours – 7 days)

| Property | Value |
|----------|-------|
| File format | Apache Parquet v2 |
| Compression | ZSTD level 1 |
| Row group size | ~1M rows, 128MB |
| File target | 256MB uncompressed |
| Roll trigger | 256MB OR hour boundary |
| Partition | `events/{tenant_id}/{yyyy-mm-dd}/{hh}/part-NNNN.parquet` |
| Sorted by | `(agent_id, ts_us)` within each file |
| Timestamps | INT64 epoch microseconds |
| Compaction | Hourly → daily files after 48 hours |

**Why no agent in partition path:** 1000 agents × 24 hours = 24,000 files/day. Tiny files destroy compression and query performance. Agent ID is a sort column; Parquet's dictionary encoding + min/max row group stats provide the same pruning without the file explosion.

### Cold: Parquet (7 days+)

| Property | Value |
|----------|-------|
| Retention | TTL per compliance framework |
| Deletion | Manifest status → `expired` → grace period → delete |
| Integrity | Weekly scrub: re-hash committed files |

---

## Schema

### Hot Table (one per hour)

```sql
CREATE TABLE edr_events_{yyyymmddhh} (
    id          TEXT PRIMARY KEY,     -- UUIDv7
    tenant_id   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    ts_us       INTEGER NOT NULL,     -- epoch microseconds
    ingested_at INTEGER NOT NULL,     -- for lateness auditing

    -- Columnar-decomposed JSON fields
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
    data_raw    BLOB                  -- zstd-compressed if >4KB
);

CREATE INDEX idx_{yyyymmddhh}_ts ON edr_events_{yyyymmddhh}(ts_us);
```

### Manifest (separate SQLite database)

```sql
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

CREATE UNIQUE INDEX idx_pf_path ON parquet_files(path);
CREATE INDEX idx_pf_lookup ON parquet_files(tenant_id, status, min_ts_us, max_ts_us);

CREATE TABLE watermark (
    id       INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    last_id  TEXT NOT NULL,                         -- UUIDv7 high-water mark
    last_ts  INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE hot_tables (
    table_name TEXT PRIMARY KEY,
    hour_start INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active'
    -- active | flushed | dropped
);
```

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **SQLite is the WAL** | All ingestion lands in SQLite. Single fsync per batch. ~1–2 hours of data. |
| **Hourly tables, DROP TABLE retention** | DELETE on billions of rows is disqualifying. DROP TABLE = O(1). |
| **Dedicated writer goroutine** | Removes SQLite writer-lock contention. N workers feed it over a channel. |
| **Single index on hot table: (ts_us)** | Every extra index is write-amplification tax. Rich indexing is Parquet's job. |
| **Columnar-decomposed schema** | 5–10 hot JSON fields → real columns. This is where 10–20× compression comes from. |
| **Watermark-driven flusher** | Re-reads from SQLite (page cache = free). Atomic manifest commit per file. Exactly-once semantics. |
| **Manifest is single source of truth** | Not filesystem glob. Not wall clock. Router cutoff = watermark. No boundary race. |
| **Partition by {tenant}/{date}/{hour}** | NOT by agent. Agent is sort column. Parquet handles pruning via dictionary + min/max. |
| **Pure-Go fallback reader** | Default CGO-free build reads its own canonical data. DuckDB is optional performance upgrade. |
| **Weekly integrity scrub** | Re-hashes committed files. Detects bit rot before incident response. |
| **Event ID = UUIDv7** | Time-sortable, no DB dependency, survives Parquet → S3 → distributed merge. |
| **Cursors instead of offsets** | UUIDv7 = free pagination token. Offset is quadratic under concurrent writes. |

---

## Ingestion Pipeline

### Queue

```go
type IngestQueue struct {
    ch      chan *Event        // cap: 65536 (≥1s buffer at 50K/s)
    spill   *DiskSpill         // segment files, used when ch full
    dropped atomic.Uint64      // last resort; alert on any increment
}

func (q *IngestQueue) Enqueue(e *Event) error {
    select {
    case q.ch <- e:
        return nil
    case <-time.After(100 * time.Millisecond):
        if err := q.spill.Write(e); err != nil {
            q.dropped.Add(1)
            return ErrEventDropped  // caller/collector can NACK & retry
        }
        return nil
    }
}
```

Policy hierarchy: block briefly → spill to disk → drop with counter + alert. Never silent. A SIEM that loses the events documenting the attack that overloaded it has failed at its one job.

### Batch Writer

Accumulates 1000 events or 250ms. Single transaction, single fsync. `INSERT ... ON CONFLICT(id) DO NOTHING` — idempotent, so collectors safely retry on ambiguous failures.

### Dedicated Writer Goroutine

N ingest workers feed batches to a single goroutine that owns the SQLite connection. Removes writer-lock contention entirely. The ceiling becomes NVMe throughput, not SQLite lock granularity.

---

## Flusher (Exactly-Once Semantics)

```go
func (f *Flusher) Run(ctx context.Context) {
    for {
        wm := f.manifest.GetWatermark()
        rows := f.hot.Query(ctx, Query{MinID: wm.LastID, Limit: 100000})

        groups := groupBy(rows, func(e *Event) GroupKey {
            return GroupKey{Tenant: e.TenantID, Hour: truncateHour(e.TsUs)}
        })

        for _, g := range groups.ready() {
            sort.Slice(g, byAgentIDThenTsUs)
            tempPath := f.writeTempParquet(g)   // fsync file + directory
            sha256, stats := f.checksum(tempPath)
            finalPath := f.rename(tempPath)     // atomic on POSIX

            f.manifest.Transaction(func(tx *sql.Tx) {
                tx.InsertParquetFile(finalPath, stats, status="committed")
                tx.UpdateWatermark(stats.MaxID, stats.MaxTs)
            })
        }

        f.manifest.DropFlushedTables(wm.LastID)

        select {
        case <-ctx.Done(): return
        case <-time.After(f.interval):
        }
    }
}
```

### Crash Safety Matrix

| Failure | Recovery |
|---------|----------|
| Crash during SQLite batch write | Transaction rolls back. Collector retries. ON CONFLICT DO NOTHING absorbs partial retries. |
| Crash mid-Parquet write | Watermark not advanced. Orphan temp file GC'd on startup. Flusher re-reads same rows. Zero loss, zero duplicates. |
| Crash between fsync and manifest commit | File on disk but not in manifest → orphan GC. Watermark unchanged. Same rows re-flushed. |
| Crash after manifest commit | Watermark advanced. Rows never re-flushed. File is durable and registered in manifest. |
| Disk full on Parquet volume | Flusher stalls, watermark frozen. Hot retention refuses DROP. SQLite grows as buffer. Ingest keeps working. |
| Disk full on SQLite volume | Backpressure → spill → collector NACK. Events refused, never silently lost. |

This is the property that simpler architectures (dual-write, no archiver) cannot provide at any price. It costs one page-cache read of data written seconds ago.

---

## Query Router

```go
func (r *Router) Query(ctx context.Context, q Query) (*Result, error) {
    wm := r.manifest.Watermark()
    boundary := wm.Timestamp
    overlap := 10 * time.Minute

    var res Result
    var g errgroup.Group

    if q.Overlaps(boundary.Add(-overlap), maxTime) {
        g.Go(func() error {
            ev, err := r.hot.Query(ctx, q.ClampSince(boundary.Add(-overlap)))
            if err != nil { res.AddWarning("hot tier: %v", err); return nil }
            res.AppendHot(ev); return nil
        })
    }
    if q.Overlaps(minTime, boundary.Add(overlap)) {
        g.Go(func() error {
            files := r.manifest.FilesFor(q.TenantID, q.Since, q.Until)
            ev, err := r.cold.QueryFiles(ctx, files, q.ClampUntil(boundary.Add(overlap)))
            if err != nil { res.AddWarning("cold tier: %v", err); return nil }
            res.AppendCold(ev); return nil
        })
    }

    g.Wait()
    res.MergeSortDedupByID()
    res.ApplyLimitOffset(q)
    return &res, nil
}
```

### Pagination (Cursor-Based)

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

UUIDv7 makes the cursor free: it is simultaneously the sort key, dedup key, and pagination token.

---

## Compaction

```go
func (c *Compactor) Run(ctx context.Context) {
    for each (tenant, day) older than 48h with committed hourly files:
        1. Read all part files for the day
        2. Re-sort by (agent_id, ts_us)
        3. Write day.parquet to temp, fsync, checksum
        4. One manifest transaction:
             INSERT day file (status='committed')
             UPDATE hourly files SET status='superseded'
        5. GC: delete superseded files after 1h grace period
}
```

---

## Fallback Reader (CGO-Free Default Build)

The default build includes a pure-Go Parquet reader that evaluates simple `field = value` AND `ts BETWEEN` predicates with row-group pruning. Slower than DuckDB, but the default build can read its own canonical data.

```go
// Default build — no CGO required. DuckDB is optional performance upgrade.
type ColdReader interface {
    QueryFiles(ctx context.Context, files []FileInfo, q Query) ([]*Event, error)
}
```

---

## DuckDB (Opt-In, Build-Tag Gated)

```go
//go:build duckdb
func (d *DuckDBAnalytics) QueryFiles(ctx context.Context, files []FileInfo, q Query) ([]*Event, error) {
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

```go
//go:build !duckdb
func (d *ParquetReader) QueryFiles(ctx context.Context, files []FileInfo, q Query) ([]*Event, error) {
    // Pure-Go fallback: evaluate field = value AND ts BETWEEN
    // with row-group pruning. Slower but CGO-free.
    for _, f := range files {
        reader, _ := parquet.Open(f.Path)
        for _, rg := range reader.RowGroups() {
            if !rg.MinMax("ts_us").Overlaps(q.SinceUs, q.UntilUs) {
                continue
            }
            // scan matching rows
        }
    }
}
```

---

## Implementation Phases

| Phase | Weeks | Deliverable | Verification |
|-------|-------|-------------|-------------|
| 1 | 1–2 | Hourly hot tables + registry, batch writer, dedicated writer goroutine, queue with backpressure/spill. | Crash-injection harness skeleton. |
| 2 | 3–4 | Flusher + watermark + manifest + atomic commit protocol + startup orphan GC. | Harness runs continuously from here. |
| 3 | 5 | Router (watermark cutoff, overlap merge, cursor pagination, partial-result warnings). Pure-Go fallback cold reader. | |
| 4 | 6 | DuckDB reader behind build tag, manifest-driven file lists. | |
| 5 | 7–8 | Compactor, cold-tier GC/TTL, integrity scrub, snapshots. | 50K ev/s, 24h soak, zero drops. |

---

## Benchmark Targets

| Metric | Target | Gate |
|--------|--------|------|
| Sustained ingest | 50K ev/s, 24h soak, NVMe | p99 enqueue < 50ms; zero drops |
| Flush lag (watermark age) | < 90s steady state | Alert threshold: 15 min |
| Hot query (1h, 1 agent) | < 50ms | |
| Cold query (30d, 1 tenant, sev≥5) | < 2s over ~1B rows | Requires manifest pruning working |
| Boundary query (spans watermark) | Correct merge, zero missing, zero dupes | Correctness test under crash injection |
| Compression | ≥ 10× on columnar-decomposed schema | Measured on real EDR payloads |
| Crash recovery | kill -9, 1000 iterations | Zero committed-data loss, zero duplicates |

The crash recovery benchmark is the one that matters. Build the crash-injection harness in Phase 1 — it is the executable proof that the watermark design delivers what simpler architectures cannot.

---

## Snapshots

```bash
# Quiesce flusher → snapshot manifest + hot tables + Parquet → tar.zst → resume
trace snapshot create --output trace-snapshot-2026-07-24.tar.zst
trace snapshot restore --input trace-snapshot-2026-07-24.tar.zst
```

---

## Deployment Model: Single SOC → Enterprise Multi-SOC

The same binary, the same Parquet format, the same manifest catalog — just one config change.

### Single SOC (Local Disk)

```
trace serve --tse

All data on local disk:
  /data/tse/manifest.db
  /data/tse/events.db (hot SQLite tables)
  /data/tse/events/{tenant}/{date}/{hour}/*.parquet

Postgres or SQLite for alerts, investigations, config.
```

### Enterprise Multi-SOC (S3 Object Storage)

```
trace serve --tse --storage s3://trace-bucket/events/

Each node runs TSE independently:
  /data/tse/manifest.db          ← local (per node)
  /data/tse/events.db            ← local hot tables (per node)
  s3://trace-bucket/events/...   ← shared Parquet (all nodes)

Any node queries the full dataset via DuckDB over S3:
  SELECT * FROM read_parquet('s3://trace-bucket/events/*.parquet')
```

| Aspect | Single SOC | Enterprise Multi-SOC |
|--------|-----------|---------------------|
| Storage | Local disk | S3 / MinIO / Cloudflare R2 / GCS |
| Binary | Same `trace` binary | Same `trace` binary |
| Parquet format | Same | Same |
| Manifest | Local | Local per node + optional central |
| Hot tier | Local SQLite | Local SQLite per node |
| Cold tier | Local Parquet | Shared Parquet on object storage |
| Multi-node query | N/A | DuckDB reads S3 Parquet directly |
| Durability | Disk RAID | 99.99999999% (S3) |
| Cost | Fixed hardware | Pay per GB stored |

### How Multi-SOC Works

```
SOC Node A (NYC)              SOC Node B (London)
    │                              │
    ▼                              ▼
SQLite (hot, local)          SQLite (hot, local)
    │                              │
    ▼                              ▼
Flusher ──► Parquet on S3 ◄── Flusher
                 │
                 ▼
          Manifest (optional central)
                 │
                 ▼
    Any node queries all Parquet via DuckDB read_parquet('s3://...')
```

Each node writes Parquet files to the same S3 bucket. The files are partitioned by `{tenant}/{date}/{hour}`, so there's no conflict. DuckDB can query any subset of files via `read_parquet(['s3://.../part-0001.parquet', ...])`.

The manifest per node tracks what it has written. A central manifest (optional) federates across all nodes for global queries. Without a central manifest, each node queries its own data + any S3 prefix it has access to.

### Key Insight

**You don't need a distributed system to get distributed query.** You need a shared storage layer and a query engine that can read from it. S3 + DuckDB + Parquet gives you that without the complexity of sharding, replication, or cluster coordination.

---

## What This Architecture Is

- **An LSM tree built from boring components.** SQLite = memtable+WAL. Flusher = memtable flush. Compactor = LSM compaction. Manifest = MANIFEST file. You are not avoiding the LSM architecture; you are renting its hardest parts from battle-tested components.

- **A storage engine, not a database integration.** Parquet is the canonical format. The query engine (DuckDB) is swappable. The manifest is the metadata catalog.

- **Single-node first. Multi-node via object storage.** Same binary, same format. Change one config line from local disk to S3.

---

## What It Is Not

- **Not a Lucene competitor.** SIEM queries are structured (field = value), not free-text.
- **Not a multi-node cluster in the traditional sense.** No sharding, no replication, no master election. Multi-node is achieved via shared object storage + per-node manifests.
- **Not replacing SQLite for operational data.** SQLite stays for alerts, investigations, config.

---

## Evolution Path

```
Today:        SQLite (all data on local disk)

Phase 1:      Hourly hot tables + batch writer + queue
Phase 2:      Flusher + watermark + manifest + Parquet writer
Phase 3:      Router + pure-Go cold reader
Phase 4:      DuckDB analytics (opt-in CGO)
Phase 5:      Compaction + TTL + scrub + snapshots

Enterprise:   Same binary, just change storage path:
              trace serve --tse --storage s3://trace-bucket/events/

Multi-SOC:    Each node writes to shared S3 bucket.
              Any node queries the full dataset.
              No distributed system complexity.
```

No rewrites between stages. Each phase is additive. The jump from single SOC to enterprise multi-SOC is a config change, not an architecture change.
