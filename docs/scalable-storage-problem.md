# Trace Storage Engine (TSE) — Architecture & Implementation Plan

## The Problem

SQLite is the only storage engine. It's row-oriented OLTP. At scale, it hits three walls:

| Limit | Symptom | Threshold |
|-------|---------|-----------|
| **Write throughput** | Single-writer WAL lock. 10K batched inserts/sec ≈ ceiling. | ~50K events/sec |
| **Storage bloat** | Row format + JSON blobs = no compression. 1KB/event × 1B events = 1TB. | ~100M events before pain |
| **Time-range queries** | No partitioning. Full table scans on `edr_events`. | ~100M rows = multi-second |

## Final Architecture (Peer-Reviewed)

Both independent reviews (Claude + ChatGPT) converged on the same correction: **Parquet is the canonical event store. DuckDB reads Parquet. It never stores data.**

```
                    Trace Storage Engine (TSE)
                    ═══════════════════════════

  Collectors / SIEM / Agents
         │
         ▼
  Memory Queue (MPMC ring buffer, 10k cap, non-blocking)
         │
         ├── N worker goroutines (configurable, default 4)
         │
         ▼
  Batch Writer (1000 events or 1s, whichever first)
         │
         ├──────────────────────► SQLite (hot tier, 0-7 days)
         │                            │
         │                            ├── Active investigations
         │                            ├── Recent alerts
         │                            ├── Current agent status
         │                            └── UI queries (WAL mode)
         │
         └──────────────────────► Parquet (warm/cold tier, 7 days+)
                                      │
                                      ├── Written directly from batch
                                      ├── No re-read from SQLite
                                      ├── Roll: max(256MB, 1 hour)
                                      ├── ZSTD compression (10-20x)
                                      └── Partitioned:
                                          events/{tenant}/{agent}/{year}/{month}/{day}/{hour}/part-NNNN.parquet

  Retention:
    DELETE FROM sqlite WHERE timestamp < NOW() - 7 days
    (No archiver, no re-read, no checksum verification pipeline.
     SQLite and Parquet receive the same batch simultaneously.)

  Query Router
         │
         ├── SQLite:      timestamp >= NOW() - 7 days
         ├── DuckDB:      read_parquet('events/**/*.parquet') WHERE timestamp < NOW() - 7 days
         │                (Plus SQLite for boundary overlap — UNION ALL + DISTINCT id)
         └── Merge:       sort by timestamp, dedup by id, return

  Manifest Catalog (SQLite)
         │
         ├── Tracks all Parquet files: path, min/max time, row count, checksum, schema_version
         ├── Enables DuckDB to discover files without filesystem scan
         └── Status: writing → committed → corrupted → deleted

  DuckDB (optional, build tag: duckdb)
         │
         └── SELECT * FROM read_parquet('events/*/*/*.parquet')
             WHERE severity >= 5
             GROUP BY event_type
             ORDER BY count DESC
```

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Parquet is canonical storage** | Columnar, ZSTD, filter pushdown. DuckDB reads it with `read_parquet()` — no ETL, no import, no duplication. |
| **Batch writes to both SQLite + Parquet simultaneously** | No archiver pipeline. No re-reading from SQLite. No migration. Retention is just `DELETE FROM sqlite`. |
| **UUIDv7 for event IDs** | Time-sortable, no DB dependency, survives Parquet → S3 → distributed merge without collision. |
| **EventID is the idempotency key** | `ON CONFLICT (id) DO NOTHING` on both SQLite and Parquet. Crash-safe without watermarks. |
| **No custom bitmap index** | 99% of SIEM queries are structured field = value. Parquet dictionary encoding + min/max row group pruning handles this. Full-text search on cmdline is a future DuckDB FTS extension. |
| **Opt-in DuckDB via build tag** | Default build stays CGO-free + trivial cross-compile. DuckDB analytics only when explicitly enabled. |
| **Fan-out query router** | Queries spanning the 7-day boundary hit both stores. Results merged by timestamp + deduped by ID. |

---

## Storage Tiers

### Hot: SQLite (0-7 days)

| Property | Value |
|----------|-------|
| Retention | DELETE FROM sqlite WHERE timestamp < NOW() - 7d |
| Schema | Fixed: `edr_events(id, agent_id, event_type, severity, data, timestamp, org_id)` |
| Index | idx_edr_events_agent, idx_edr_events_type, idx_edr_events_severity, idx_edr_events_time |
| WAL mode | Checkpoint every 1000 writes |

### Warm/Cold: Parquet (7 days+)

| Property | Value |
|----------|-------|
| Format | Apache Parquet v2 |
| Compression | ZSTD (level 1 for speed, configurable via `CompressionCodec` enum) |
| Row group size | ~1M events |
| File roll | `max(256MB uncompressed, 1 hour)` |
| Partition layout | `events/{tenant}/{agent}/{year}/{month}/{day}/{hour}/part-NNNN.parquet` |
| Schema version | Stored in manifest + Parquet key-value metadata |

### Partition Layout

```
data/events/
├── {tenant_id}/
│   ├── {agent_id}/
│   │   ├── 2026/
│   │   │   ├── 07/
│   │   │   │   ├── 24/
│   │   │   │   │   ├── 10/
│   │   │   │   │   │   ├── part-0001.parquet
│   │   │   │   │   │   └── part-0002.parquet
│   │   │   │   │   └── 11/
│   │   │   │   └── 25/
│   │   │   └── 08/
│   │   └── ...
```

---

## Event ID Format (UUIDv7)

```go
// UUIDv7: time-ordered UUID with millisecond precision
// |--- 48 bits Unix ms ---|---- 74 bits random ----|-- 2 bits variant --|
func NewEventID() string {
    id, _ := uuid.NewV7()
    return id.String()
}
```

Benefits:
- Time-sortable: `ORDER BY id` ≈ `ORDER BY timestamp`
- No AUTOINCREMENT dependency — survives distributed writes
- 122 bits of randomness — collision probability near zero
- Standard UUID format — all tools parse it

---

## Manifest Catalog

Stored in a separate SQLite database (`manifest.db`):

```sql
CREATE TABLE parquet_files (
    file_id         TEXT PRIMARY KEY,     -- UUIDv7
    path            TEXT NOT NULL,         -- relative path from data dir
    tenant_id       TEXT NOT NULL DEFAULT '',
    agent_id        TEXT NOT NULL DEFAULT '',
    min_timestamp   TEXT NOT NULL,         -- RFC3339
    max_timestamp   TEXT NOT NULL,
    min_event_id    TEXT NOT NULL,
    max_event_id    TEXT NOT NULL,
    row_count       INTEGER NOT NULL,
    compressed_size INTEGER NOT NULL,      -- bytes
    uncompressed_size INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    compression     TEXT NOT NULL DEFAULT 'zstd',
    schema_version  INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'writing',  -- writing | committed | corrupted | deleted
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_manifest_time ON parquet_files(min_timestamp, max_timestamp);
CREATE INDEX idx_manifest_tenant ON parquet_files(tenant_id);
```

---

## Compression Codec (Enum, Not Hardcoded)

```go
type CompressionCodec string

const (
    CompressionZSTD   CompressionCodec = "zstd"
    CompressionSnappy CompressionCodec = "snappy"
    CompressionLZ4    CompressionCodec = "lz4"
    CompressionBrotli CompressionCodec = "brotli"
    CompressionNone   CompressionCodec = "none"
)
```

Future codecs added without API changes.

---

## Schema Evolution

Parquet supports schema evolution natively:
- **New columns** added with default values → old files remain readable
- **Deprecated columns** skipped in queries
- Schema version stored in:
  - `manifest.parquet_files.schema_version`
  - Parquet file key-value metadata

DuckDB handles mixed-schema reads: columns missing from older files return NULL.

---

## Interfaces

```go
// Writer — ingestion path
type Writer interface {
    WriteBatch(ctx context.Context, events []*Event) error
    Close() error
}

// Reader — query path
type Reader interface {
    Query(ctx context.Context, q Query) ([]*Event, error)
}

// Retention — lifecycle management
type Retention interface {
    DeleteOlderThan(ctx context.Context, cutoff time.Time) (int, error)
}

type Query struct {
    TenantID    string
    AgentIDs    []string
    EventTypes  []string
    MinSeverity int
    Since, Until time.Time
    Limit       int
    Offset      int
}
```

### Implementations

| Type | Implementation | Build tag | CGO |
|------|---------------|-----------|-----|
| Writer + Reader + Retention | `SQLiteStore` | (none) | No |
| Writer | `ParquetWriter` | (none, pure Go via go-parquet) | No |
| Reader | `DuckDBAnalytics` | `duckdb` | Yes |
| Composite | `StorageRouter` | (none) | No |

---

## Queue Architecture

```
Collector goroutines
    │
    ▼
MPMC ring buffer (channel, cap=10000, non-blocking send)
    │
    ├── Worker 1 (goroutine)
    ├── Worker 2 (goroutine)
    ├── Worker 3 (goroutine)
    └── Worker N (goroutine, default 4)
         │
         ▼
    Batch (accumulate 1000 events or 1s)
         │
         ├── SQLiteStore.WriteBatch(ctx, batch)
         └── ParquetWriter.WriteBatch(ctx, batch)
```

Multiple workers prevent head-of-line blocking. If one Parquet file write stalls, other workers continue processing.

---

## Query Router (Fan-Out)

```go
func (r *Router) Query(ctx context.Context, q Query) ([]*Event, error) {
    if q.Since == nil || time.Since(*q.Since) < 7*24*time.Hour {
        // Query spans hot data — hit SQLite
        hotEvents, _ := r.hot.Query(ctx, q)
        return hotEvents, nil
    }

    // Fan-out: query both stores, merge
    var wg sync.WaitGroup
    var hot, cold []*Event

    if q.Since.Before(time.Now().Add(-7 * 24 * time.Hour)) {
        wg.Add(1)
        go func() {
            defer wg.Done()
            cold, _ = r.cold.Query(ctx, q)
        }()
    }
    if q.Until == nil || q.Until.After(time.Now().Add(-7*24*time.Hour)) {
        wg.Add(1)
        go func() {
            defer wg.Done()
            hot, _ = r.hot.Query(ctx, q)
        }()
    }
    wg.Wait()

    // Merge + dedup by ID
    return mergeEvents(append(hot, cold...)), nil
}
```

---

## DuckDB Dependency

```go
// analytics_duckdb.go — go build -tags duckdb
//go:build duckdb

func (d *DuckDBAnalytics) Query(ctx context.Context, q Query) ([]*Event, error) {
    db, _ := sql.Open("duckdb", "")
    rows, _ := db.QueryContext(ctx, `
        SELECT * FROM read_parquet('data/events/**/*.parquet')
        WHERE timestamp >= ? AND timestamp < ?
        AND severity >= ?
    `, q.Since, q.Until, q.MinSeverity)
    return scanEvents(rows)
}
```

```go
// analytics_stub.go — default build, no CGO
//go:build !duckdb

func (d *DuckDBAnalytics) Query(ctx context.Context, q Query) ([]*Event, error) {
    return nil, fmt.Errorf("DuckDB analytics requires CGO: go build -tags duckdb")
}
```

---

## Benchmark Target

| Metric | Target | Hardware |
|--------|--------|----------|
| Sustained write | 50K events/sec | NVMe SSD, ZSTD level 1 |
| Batch size | 1000 events | MPMC queue |
| Compression | 10-20x | ZSTD, depends on field cardinality |

---

## Snapshots

```bash
# Create a full snapshot of all state
trace snapshot create --output trace-snapshot-2026-07-24.tar.zst

# Restore from snapshot
trace snapshot restore --input trace-snapshot-2026-07-24.tar.zst
```

Snapshot contents:
- `manifest.db` (Parquet file catalog)
- `events.db` (SQLite hot tier)
- `events/` (Parquet files, max 7 days)
- `config.json`

---

## What This Makes Possible

| Before | After |
|--------|-------|
| SQLite falls over at 100M events | Parquet handles 100B+ events |
| Queries on old data = full table scan | DuckDB reads only matching row groups |
| Retention = manual DELETE FROM | Automated `DELETE FROM sqlite WHERE ...` |
| Archiver re-reads SQLite → double I/O | Batch writes to both simultaneously — no re-read |
| Multi-node = impossible | Parquet on S3 → any node queries it |
| CGO required for analytics | Default build stays CGO-free |
| Event IDs = SQLite AUTOINCREMENT | UUIDv7 — survives distributed writes |

---

## What This Is Not

- **Not a Lucene competitor** — SIEM queries are structured (field = value), not free-text. Parquet dictionary encoding + min/max row group pruning covers 99% of queries.
- **Not a multi-node cluster** — single node. Multi-node is future work via Parquet on object storage.
- **Not replacing SQLite** — SQLite stays for operational data (alerts, investigations, recent events). Only event data migrates to Parquet.

---

## Evolution Path

```
Today:
  SQLite (all data)

Tomorrow:
  SQLite (hot) + Parquet (warm) + DuckDB (analytics)

Enterprise:
  SQLite (hot) + Parquet on S3 + any query engine (DuckDB / DataFusion / Polars)

Future (distributed):
  Per-node SQLite + Parquet on shared object store
  Cross-node query via manifest catalog
```

No rewrites at any stage. Each tier is additive. DuckDB is just one query backend — if a pure-Go analytical engine emerges (Apache DataFusion, Polars), swap it in without changing the storage format.
