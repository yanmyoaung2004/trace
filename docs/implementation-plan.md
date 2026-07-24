# Trace Storage Engine — Implementation Plan

## 1. Project Overview

**Goal:** Build the Trace Storage Engine (TSE) — a Go-native, embedded, columnar time-series event store that replaces SQLite-only storage with a hot/warm/cold tiered architecture supporting 50K events/sec ingest over a single binary.

**Finished system achieves:**
- 50K events/sec sustained ingest (NVMe)
- 10-20x compression on event data (Parquet + ZSTD + columnar decomposition)
- Sub-second queries over 30 days of data (~1B events)
- Exactly-once crash semantics (watermark-driven flusher)
- Dual deployment: local disk for single SOC, S3 for enterprise multi-SOC
- Pure-Go default build, DuckDB as optional CGO performance upgrade

---

## 2. Dependency Graph

```
Queue (no deps)
  │
  ▼
Batch Writer (depends: Queue)
  │
  ├──► SQLite Hot Tables (depends: Batch Writer)
  │         │
  │         ▼
  │    Dedicated Writer Goroutine (depends: SQLite)
  │
  ├──► Manifest (no deps — can be built in parallel)
  │
  ▼
Flusher (depends: SQLite Hot Tables, Manifest, Parquet Writer)
  │
  ▼
Parquet Writer (depends: Manifest — can be built in parallel with SQLite)
  │
  ▼
Router (depends: SQLite Hot Tables, Manifest, Cold Reader)
  │
  ├──► Cold Reader / Parquet Reader (depends: Manifest)
  │
  ├──► DuckDB Adapter (depends: Manifest, optional CGO)
  │
  ▼
Compactor (depends: Manifest, Parquet Reader)
  │
  ▼
Snapshots (depends: Flusher, Manifest, SQLite Hot Tables)
  │
  ▼
GC / Integrity Scrub (depends: Manifest)
```

**Parallel build groups:**
- Group A: Queue + Batch Writer + SQLite Hot Tables (core ingest pipeline)
- Group B: Manifest (independent, needed by everything downstream)
- Group C: Parquet Writer (independent of A, depends only on Manifest)
- Group D: Flusher (joins A + B + C)
- Group E: Router + Cold Reader + DuckDB Adapter (query path)
- Group F: Compactor + GC + Scrub + Snapshots (operational)

---

## 3. Development Phases

### Phase 0: Foundation (Week 1)

**Goal:** Implement core interfaces, data models, and the Queue + Batch Writer + dedicated writer goroutine.

**Deliverables:**
- All interfaces defined (Writer, Reader, Retention, Flusher, Compactor, GC)
- All data models/structs defined (Event, Query, Result, FileInfo, Watermark, ParquetFileRecord, HotTableRecord)
- IngestQueue with backpressure (block → spill → count drops)
- BatchWriter accumulating 1000 events or 250ms
- DedicatedWriterGoroutine pattern (channel from N workers → single SQLite writer)

**Dependencies:** None (pure Go, no storage dependencies yet)

**Estimated complexity:** Medium

**Risks:** Getting the channel/goroutine pattern wrong leads to deadlocks. Mitigate with timeout-based selects and a spill-to-disk fallback tested under load.

**Acceptance criteria:**
- Queue enqueues 50K events/sec without dropping
- Batch writer produces 1K-event batches every 250ms at 50K/s
- Writer goroutine commits 40 transactions/sec sustained
- Crash-injection harness skeleton runs (kill -9, verify no committed-data loss)

**Expected output:** Core ingest pipeline with proven throughput but no persistent storage yet.

---

### Phase 1: SQLite Hot Tables (Week 2)

**Goal:** Implement hourly hot tables with CREATE/DROP lifecycle.

**Deliverables:**
- hot_tables registry in manifest
- Hourly table creation (edr_events_{yyyymmddhh})
- Batched INSERT with ON CONFLICT(id) DO NOTHING
- Hot table reader (time-range + field filter queries over UNION ALL of live hourly tables)
- DROP TABLE behind watermark (only tables fully flushed + safety margin)
- Read-only connection pool for UI queries
- Passive checkpointing goroutine

**Dependencies:** Phase 0 (Queue + Writer Goroutine), Manifest (for hot_tables registry)

**Estimated complexity:** Medium

**Risks:** DROP TABLE race if table still has unflushed data. Mitigated by watermark check + safety margin. Schema migration if columns change — handled by Parquet schema version, not hot tables.

**Acceptance criteria:**
- 50K events/sec sustained insert into hourly tables
- Hot query (last 1h, 1 agent) < 50ms
- DROP TABLE behind watermark works without data loss
- Read-only pool doesn't block writes
- 24h soak with zero errors

**Expected output:** Hot tier operational. All data survives restart.

---

### Phase 2: Manifest + Parquet Writer (Weeks 2-3, parallel with Phase 1)

**Goal:** Build the manifest catalog and the Parquet file writer.

**Deliverables:**
- Manifest transactions (INSERT parquet_files + UPDATE watermark in single txn)
- Watermark singleton table with CHECK(id=1)
- ParquetWriter: accumulate → sort by (agent_id, ts_us) → write to temp → fsync → checksum → atomic rename → manifest commit
- Startup orphan GC (delete files on disk not in manifest)
- Columnar schema: 5-10 hot JSON fields decomposed, data_raw BLOB for residual
- CompressionCodec enum (ZSTD default, Snappy/LZ4/Brotli as options)
- INT64 epoch microseconds for timestamps

**Dependencies:** Manifest (Phase 2a, no deps), ParquetWriter (Phase 2b, depends on Manifest)

**Estimated complexity:** High (Parquet writer is the most complex new component)

**Risks:** Parquet writer performance (serialization, sorting, compression). Mitigate by profiling early with real event data. Manifest transaction atomicity — test under crash injection.

**Acceptance criteria:**
- ParquetWriter produces valid Parquet v2 files
- Files are sorted by (agent_id, ts_us) within each file
- Atomic rename + manifest commit survives crash injection
- Orphan GC deletes temp files on startup
- 256MB file target reached within 1 hour at 50K/s
- Compression ≥ 8x on real EDR payloads

**Expected output:** Parquet files on disk with manifest tracking. Hot data remains in SQLite.

---

### Phase 3: Flusher + Retention (Week 4)

**Goal:** Connect the hot tier to the cold tier via the watermark-driven flusher.

**Deliverables:**
- Flusher: reads id > watermark from SQLite → accumulates by (tenant, hour) → sorts → delegates to ParquetWriter → commits manifest → advances watermark
- Retention: DROP TABLE behind watermark + safety margin
- Flusher single-goroutine ownership of watermark (no parallelism, exactly-once)

**Dependencies:** Phase 1 (SQLite Hot Tables), Phase 2 (Manifest + ParquetWriter)

**Estimated complexity:** Medium

**Risks:** Flusher falls behind ingest (watermark age grows). Mitigate by alerting at 15 min watermark age and scaling ParquetWriter throughput. Late-arriving events (clock skew) — routed to partition by event timestamp, not arrival time, with ingested_at field for auditing.

**Acceptance criteria:**
- Watermark age < 90s steady state at 50K/s
- Crash during Parquet write → watermark not advanced → retry = zero duplicates
- Crash after manifest commit → watermark advanced → zero data loss
- Late events routed to correct time partition
- Orphan files from crashed flushes GC'd on startup
- Retention drops tables behind watermark without error

**Expected output:** Full hot → cold pipeline operational. Exactly-once semantics proven under crash injection.

---

### Phase 4: Query Router + Cold Reader (Week 5)

**Goal:** Implement the query path that transparently merges hot and cold data.

**Deliverables:**
- Router: watermark cutoff, overlap merge with 10 min boundary, dedup by UUIDv7
- Pure-Go ColdReader (ParquetReader with row-group pruning for field = value AND ts BETWEEN)
- Cursor-based pagination (Query.Cursor = last UUIDv7 seen)
- Partial-result warnings (cold tier error → return hot results + warning, not failure)
- Manifest-driven file list (query manifest for files by tenant + time range, NOT filesystem glob)

**Dependencies:** Phase 1 (SQLite Hot Tables for hot queries), Phase 2 (Manifest + ParquetReader), Phase 3 (watermark is defined)

**Estimated complexity:** Medium

**Risks:** Boundary overlap query returns duplicate events. Mitigated by UUIDv7 dedup merge. Cold reader performance — pure Go may be 5-10x slower than DuckDB but acceptable for default build. Partial-result design tested with simulated cold tier failures.

**Acceptance criteria:**
- Router merges hot + cold correctly across boundary
- Open-ended queries (Since = nil) return full dataset
- Cursor-based pagination: 1000 events/page, consistent under concurrent writes
- Boundary query: zero missing, zero duplicates (tested under crash injection)
- Cold query (30d, 1 tenant) < 2s on pure-Go reader, < 100ms on DuckDB

**Expected output:** Query path covers the full time range. Default build queries without CGO.

---

### Phase 5: DuckDB Adapter (Week 6, optional CGO)

**Goal:** Implement the DuckDB analytics reader behind a build tag.

**Deliverables:**
- DuckDBAnalytics implementing ColdReader interface
- Manifest-to-file-list conversion: committed files only, pruned by tenant/time
- Build tag: //go:build duckdb
- Pure-Go stub for default build

**Dependencies:** Phase 2 (Manifest), Phase 4 (ColdReader interface)

**Estimated complexity:** Low (DuckDB Go bindings handle most complexity)

**Risks:** CGO cross-compile matrix. Mitigated by build-tag gate — DuckDB is optional, default build is CGO-free.

**Acceptance criteria:**
- DuckDB queries return same results as pure-Go reader on same Parquet files
- 5-10x faster than pure-Go reader on cold queries
- Build with -tags duckdb works on linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64
- Default build (go build) has zero CGO dependencies

**Expected output:** Performance upgrade path available. Default build unchanged.

---

### Phase 6: Compactor + GC + Scrub (Week 7)

**Goal:** Long-term operational health — compaction, TTL-based retention, integrity verification.

**Deliverables:**
- Compactor: hourly files older than 48h → read → re-sort → write daily file → manifest atomic swap
- GC: files with status=expired → grace period → delete → status=deleted (audit trail)
- Integrity scrubber: weekly low-priority pass re-hashing committed files → status=corrupted on mismatch
- TTL per compliance framework (PCI: 1y, HIPAA: 6y, default: 90d)
- trace tse scrub manual trigger command
- trace tse compact manual trigger command

**Dependencies:** Phase 2 (Manifest, ParquetReader), Phase 3 (ParquetWriter)

**Estimated complexity:** Medium

**Risks:** Compaction running concurrently with queries reads superseded files → reader must snapshot file list at query start. Mitigated by grace period (1h before deleting superseded files). Scrubber I/O contention — low priority pass with configurable IOPS limit.

**Acceptance criteria:**
- Compaction: hourly → daily files, manifest atomic swap, 1h grace period
- TTL: files with max_timestamp < cutoff get status=expired → deleted after grace
- Scrub: bit rot detection alerts before files are queried in incident response
- All three pass crash injection testing

**Expected output:** Long-term storage management operational. Data lifecycle automated.

---

### Phase 7: Snapshots + Observability (Week 8)

**Goal:** Operational maturity — backup/restore, metrics, production readiness.

**Deliverables:**
- trace snapshot create: quiesce flusher → snapshot manifest + hot tables + recent Parquet → tar.zst → resume
- trace snapshot restore: extract → validate checksums → resume flusher from watermark
- Metrics: ingest rate, queue depth, batch latency, watermark age, Parquet write speed, hot table count, cold file count, compression ratio, drop counter
- Admin commands: trace tse status, trace tse flush (force flush), trace tse inspect (list files/watermark)
- Configuration: tse.storage.path, tse.compression, tse.hot.window, tse.cold.ttl

**Dependencies:** All previous phases

**Estimated complexity:** Low-Medium

**Risks:** None significant — this is polish.

**Acceptance criteria:**
- Snapshot creates restorable backup with zero data loss
- Snapshot restore recovers to exact state before snapshot
- Metrics exported via /metrics endpoint (Prometheus)
- All admin commands functional
- Configuration documented and validated

**Expected output:** Production-ready storage engine.

---

## 4. Repository Structure

```
internal/storage/
├── config.go                    # TSE configuration (path, compression, hot window, cold TTL)
├── config_test.go
│
├── queue/
│   ├── queue.go                 # IngestQueue (chan, spill, drop counter)
│   ├── queue_test.go
│   └── spill.go                 # DiskSpill (segment files for overflow)
│
├── batch/
│   ├── writer.go                # BatchWriter (accumulate 1000 or 250ms)
│   ├── writer_test.go
│   └── writer_goroutine.go      # DedicatedWriterGoroutine (owns SQLite conn)
│
├── sqlite/
│   ├── hot_store.go             # SQLiteHotStore (hourly tables, INSERT, DROP)
│   ├── hot_store_test.go
│   ├── hot_reader.go            # HotReader (UNION ALL over live tables)
│   ├── hot_reader_test.go
│   ├── checkpoint.go            # Passive checkpoint goroutine
│   ├── checkpoint_test.go
│   └── migrations.go            # Schema versioning
│
├── manifest/
│   ├── manifest.go              # Manifest (parquet_files, watermark, hot_tables)
│   ├── manifest_test.go
│   ├── transactions.go          # Atomic manifest commits
│   ├── transactions_test.go
│   ├── lookups.go               # Query manifest for files by tenant/time
│   ├── lookups_test.go
│   └── startup.go               # Orphan GC on startup
│
├── parquet/
│   ├── writer.go                # ParquetWriter (accumulate → sort → temp → fsync → rename)
│   ├── writer_test.go
│   ├── reader.go                # ParquetReader (pure-Go, row-group pruning)
│   ├── reader_test.go
│   ├── schema.go                # Columnar schema definition
│   ├── schema_test.go
│   └── compression.go           # CompressionCodec enum + ZSTD/Snappy/LZ4/Brotli
│
├── flusher/
│   ├── flusher.go               # Flusher (watermark-driven, single goroutine)
│   ├── flusher_test.go
│   ├── groups.go                # Accumulate by (tenant, hour)
│   └── groups_test.go
│
├── router/
│   ├── router.go                # QueryRouter (watermark cutoff, overlap merge, dedup)
│   ├── router_test.go
│   ├── pagination.go            # Cursor-based pagination
│   └── pagination_test.go
│
├── cold/
│   ├── reader.go                # ColdReader interface
│   ├── parquet_reader.go        # Pure-Go ParquetReader implementation
│   ├── parquet_reader_test.go
│   ├── duckdb.go                # DuckDBAnalytics (build tag: duckdb)
│   ├── duckdb_test.go
│   └── duckdb_stub.go           # Default build stub
│
├── compactor/
│   ├── compactor.go             # Compactor (hourly → daily, atomic swap)
│   ├── compactor_test.go
│   └── planner.go               # Decide which files to compact
│
├── gc/
│   ├── gc.go                    # GC (expired files → delete → audit trail)
│   ├── gc_test.go
│   ├── scrub.go                 # Integrity scrub (weekly, low-priority)
│   └── scrub_test.go
│
├── snapshot/
│   ├── create.go                # snapshot create (quiesce → tar.zst → resume)
│   ├── create_test.go
│   ├── restore.go               # snapshot restore (extract → validate → resume)
│   └── restore_test.go
│
├── metrics/
│   └── metrics.go               # Prometheus metrics
│
├── admin/
│   └── commands.go              # trace tse subcommands (status, flush, inspect, scrub, compact)
│
└── harness/
    └── crash.go                 # Crash-injection test harness (kill -9 at random points)
```

---

## 5. Component Breakdown

### Queue (internal/storage/queue/queue.go)

**Purpose:** Buffered ingest pipeline with backpressure.

**Dependencies:** None

**Public API:**
```go
type IngestQueue struct { ... }
func NewIngestQueue(cap int, spillDir string) *IngestQueue
func (q *IngestQueue) Enqueue(ctx context.Context, e *Event) error
func (q *IngestQueue) Dequeue() <-chan *Event
func (q *IngestQueue) Len() int
func (q *IngestQueue) Dropped() uint64
func (q *IngestQueue) Close() error
```

**Concurrency model:** Multiple collectors enqueue concurrently (channel send). Single Dequeue consumer feeds the batch writer.

**Testing strategy:** Enqueue at 50K/s, verify no drops up to capacity. Verify spill works when channel full. Verify dropped counter increments at limit.

---

### Batch Writer (internal/storage/batch/writer.go)

**Purpose:** Accumulate events into batches for efficient SQLite writing.

**Dependencies:** Queue

**Public API:**
```go
type BatchWriter struct { ... }
func NewBatchWriter(batchSize int, batchTimeout time.Duration) *BatchWriter
func (w *BatchWriter) Run(ctx context.Context, events <-chan *Event, sink func(context.Context, []*Event) error)
```

**Concurrency model:** Single goroutine consuming from queue channel and producing batches to writer goroutine channel.

---

### SQLite Hot Store (internal/storage/sqlite/hot_store.go)

**Purpose:** Hourly table management + batched INSERT.

**Dependencies:** Manifest (for hot_tables registry)

**Public API:**
```go
type SQLiteHotStore struct { ... }
func NewSQLiteHotStore(path string) (*SQLiteHotStore, error)
func (s *SQLiteHotStore) WriteBatch(ctx context.Context, events []*Event) error
func (s *SQLiteHotStore) Query(ctx context.Context, q Query) ([]*Event, error)
func (s *SQLiteHotStore) EnsureHourlyTable(ctx context.Context, hourStart time.Time) error
func (s *SQLiteHotStore) DropTable(ctx context.Context, tableName string) error
func (s *SQLiteHotStore) LiveTables(ctx context.Context) ([]string, error)
func (s *SQLiteHotStore) Close() error
```

**Concurrency model:** Single writer connection owned by dedicated goroutine. Read-only connection pool shared by UI/API queries. Writer never blocks on readers (WAL mode).

---

### Manifest (internal/storage/manifest/manifest.go)

**Purpose:** Single source of truth for all committed Parquet files and the watermark.

**Dependencies:** None (independent of all other components)

**Public API:**
```go
type Manifest struct { ... }
func NewManifest(path string) (*Manifest, error)
func (m *Manifest) AddFile(ctx context.Context, file ParquetFileRecord) error
func (m *Manifest) UpdateWatermark(ctx context.Context, lastID string, lastTS int64) error
func (m *Manifest) Watermark(ctx context.Context) (*Watermark, error)
func (m *Manifest) FilesFor(ctx context.Context, tenantID string, since, until time.Time, status string) ([]FileInfo, error)
func (m *Manifest) RegisterHotTable(ctx context.Context, tableName string, hourStart int64) error
func (m *Manifest) DropHotTable(ctx context.Context, tableName string) error
func (m *Manifest) Transaction(ctx context.Context, fn func(*sql.Tx) error) error
func (m *Manifest) Close() error
```

**Key design:** Transaction() is the core method — all manifest mutations go through a single function that handles BEGIN/COMMIT/ROLLBACK. This ensures atomicity for the critical "INSERT file + UPDATE watermark" operation.

---

### Parquet Writer (internal/storage/parquet/writer.go)

**Purpose:** Write Parquet v2 files with columnar schema, ZSTD compression, sorted rows.

**Dependencies:** Manifest (for atomic commit)

**Public API:**
```go
type ParquetWriter struct { ... }
func NewParquetWriter(opts ParquetOptions) *ParquetWriter
func (w *ParquetWriter) WriteBatch(ctx context.Context, events []*Event) (*FileResult, error)
func (w *ParquetWriter) WriteSortedBatch(ctx context.Context, events []*Event) (*FileResult, error)
func (w *ParquetWriter) TempPath() string
func (w *ParquetWriter) FinalPath(tempPath string) string
```

**Key pattern:** Write to temp path → fsync → compute SHA-256 → atomic rename → manifest commit. Never write directly to final path.

---

### Flusher (internal/storage/flusher/flusher.go)

**Purpose:** Read from SQLite behind watermark, accumulate, write Parquet, commit manifest.

**Dependencies:** SQLite Hot Store, Manifest, Parquet Writer

**Public API:**
```go
type Flusher struct { ... }
func NewFlusher(hot *SQLiteHotStore, manifest *Manifest, parquet *ParquetWriter, interval time.Duration) *Flusher
func (f *Flusher) Run(ctx context.Context) error
func (f *Flusher) Watermark(ctx context.Context) (*Watermark, error)
func (f *Flusher) FlushNow(ctx context.Context) error
```

**Concurrency model:** Single goroutine. Reads watermark, reads SQLite, accumulates, writes Parquet, commits manifest.

---

### Router (internal/storage/router/router.go)

**Purpose:** Transparent hot/cold query routing with overlap merge.

**Dependencies:** SQLite Hot Store (for hot queries), ColdReader (for cold queries), Manifest (for watermark)

**Public API:**
```go
type Router struct { ... }
func NewRouter(hot *SQLiteHotStore, cold ColdReader, manifest *Manifest) *Router
func (r *Router) Query(ctx context.Context, q Query) (*Result, error)
func (r *Router) QueryWithCursor(ctx context.Context, q Query) (*Result, error)
```

---

### Cold Reader (internal/storage/cold/reader.go)

**Purpose:** Interface + pure-Go implementation + optional DuckDB adapter.

**Public API:**
```go
type ColdReader interface {
    QueryFiles(ctx context.Context, files []FileInfo, q Query) ([]*Event, error)
    Name() string
}
```

**Implementations:**
- ParquetReader — pure-Go, default build, row-group pruning, CGO-free
- DuckDBAnalytics — CGO, build tag duckdb, 5-10x faster

---

### Compactor (internal/storage/compactor/compactor.go)

**Purpose:** Merge hourly Parquet files into daily files after 48h.

**Dependencies:** Manifest, ParquetReader, ParquetWriter

---

### GC (internal/storage/gc/gc.go)

**Purpose:** Delete expired Parquet files with audit trail.

**Dependencies:** Manifest

---

### Scrub (internal/storage/gc/scrub.go)

**Purpose:** Weekly re-hash of committed files → detect bit rot.

**Dependencies:** Manifest

---

### Snapshot (internal/storage/snapshot/create.go, restore.go)

**Purpose:** Backup/restore of full TSE state.

**Dependencies:** Flusher, Manifest, SQLite Hot Store

---

## 6. Task Breakdown

### Phase 0 Tasks (Foundation)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-001 | Define Event, Query, Result, FileInfo, Watermark data models | internal/storage/types.go (new) | None | 2h |
| TSE-002 | Define Writer, Reader, Retention, Flusher, Compactor interfaces | internal/storage/interfaces.go (new) | TSE-001 | 2h |
| TSE-003 | Implement IngestQueue with channel + spill + drop counter | internal/storage/queue/queue.go, spill.go | TSE-001 | 4h |
| TSE-004 | Implement DiskSpill (segment files for overflow) | internal/storage/queue/spill.go | TSE-003 | 3h |
| TSE-005 | Implement BatchWriter (accumulate 1000 events / 250ms) | internal/storage/batch/writer.go | TSE-001 | 3h |
| TSE-006 | Implement DedicatedWriterGoroutine pattern | internal/storage/batch/writer_goroutine.go | TSE-005 | 3h |
| TSE-007 | Implement TSE config struct + defaults | internal/storage/config.go | None | 1h |
| TSE-008 | Build crash-injection harness skeleton | internal/storage/harness/crash.go | None | 4h |
| TSE-009 | Queue throughput benchmark (50K/s target) | benchmark/queue_test.go | TSE-003 | 3h |

### Phase 1 Tasks (SQLite Hot Tables)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-101 | Implement SQLiteHotStore (open, schema, hourly table creation) | internal/storage/sqlite/hot_store.go | TSE-002, TSE-007 | 4h |
| TSE-102 | Implement batched INSERT with ON CONFLICT DO NOTHING | internal/storage/sqlite/hot_store.go | TSE-101 | 2h |
| TSE-103 | Implement hot_tables registry in manifest | internal/storage/manifest/manifest.go | TSE-002 | 2h |
| TSE-104 | Implement HotReader (UNION ALL over live hourly tables) | internal/storage/sqlite/hot_reader.go | TSE-101 | 3h |
| TSE-105 | Implement DROP TABLE behind watermark | internal/storage/sqlite/hot_store.go | TSE-101, TSE-103, TSE-202 | 3h |
| TSE-106 | Implement read-only connection pool + passive checkpoint | internal/storage/sqlite/checkpoint.go | TSE-101 | 2h |
| TSE-107 | SQLite hot store integration test (24h soak at 50K/s) | internal/storage/sqlite/hot_store_test.go | TSE-101, TSE-102 | 4h |

### Phase 2a Tasks (Manifest)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-201 | Implement Manifest (open, schema, migrations) | internal/storage/manifest/manifest.go | None | 3h |
| TSE-202 | Implement atomic manifest transactions (BEGIN/COMMIT pattern) | internal/storage/manifest/transactions.go | TSE-201 | 3h |
| TSE-203 | Implement watermark table (singleton, CHECK id=1) | internal/storage/manifest/manifest.go | TSE-201 | 1h |
| TSE-204 | Implement manifest lookup queries (files by tenant, time, status) | internal/storage/manifest/lookups.go | TSE-201 | 2h |
| TSE-205 | Implement startup orphan GC | internal/storage/manifest/startup.go | TSE-201 | 2h |

### Phase 2b Tasks (Parquet Writer)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-211 | Define columnar schema (5-10 hot JSON fields + data_raw) | internal/storage/parquet/schema.go | TSE-001 | 2h |
| TSE-212 | Implement CompressionCodec enum | internal/storage/parquet/compression.go | None | 1h |
| TSE-213 | Implement ParquetWriter (accumulate → sort → write → fsync → rename) | internal/storage/parquet/writer.go | TSE-201, TSE-211, TSE-212 | 6h |
| TSE-214 | Parquet writer benchmark (throughput, compression, file sizes) | benchmark/parquet_test.go | TSE-213 | 4h |
| TSE-215 | Implement Pure-Go ParquetReader with row-group pruning | internal/storage/parquet/reader.go | TSE-211 | 6h |

### Phase 3 Tasks (Flusher)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-301 | Implement Flusher (watermark → SQLite read → accumulate → Parquet → commit) | internal/storage/flusher/flusher.go | TSE-101, TSE-201, TSE-213 | 6h |
| TSE-302 | Implement group accumulation by (tenant_id, hour_of_ts) | internal/storage/flusher/groups.go | TSE-301 | 3h |
| TSE-303 | Flusher crash-injection tests (1000 iterations, random kill points) | internal/storage/flusher/flusher_test.go | TSE-301, TSE-008 | 6h |
| TSE-304 | Retention: DROP TABLE behind watermark | (shared with TSE-105) | TSE-301, TSE-101 | 2h |

### Phase 4 Tasks (Query Router)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-401 | Implement ColdReader interface | internal/storage/cold/reader.go | TSE-002 | 1h |
| TSE-402 | Implement pure-Go ParquetReader (field = value, ts BETWEEN, row-group pruning) | internal/storage/cold/parquet_reader.go | TSE-215, TSE-401 | 6h |
| TSE-403 | Implement Router (watermark cutoff, fan-out, merge, dedup) | internal/storage/router/router.go | TSE-104, TSE-401, TSE-201 | 6h |
| TSE-404 | Implement cursor-based pagination | internal/storage/router/pagination.go | TSE-403 | 3h |
| TSE-405 | Implement partial-result warnings | internal/storage/router/router.go | TSE-403 | 2h |
| TSE-406 | Router integration tests (boundary correctness under crash injection) | internal/storage/router/router_test.go | TSE-403, TSE-008 | 6h |

### Phase 5 Tasks (DuckDB)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-501 | Implement DuckDBAnalytics (build tag: duckdb) | internal/storage/cold/duckdb.go | TSE-401, TSE-204 | 4h |
| TSE-502 | Implement DuckDB stub for default build | internal/storage/cold/duckdb_stub.go | TSE-401 | 1h |
| TSE-503 | DuckDB cross-compile CI matrix (linux/darwin/windows, amd64/arm64) | .github/workflows/tse.yml | TSE-501 | 2h |

### Phase 6 Tasks (Compactor + GC + Scrub)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-601 | Implement Compactor (hourly → daily, manifest atomic swap) | internal/storage/compactor/compactor.go | TSE-201, TSE-215, TSE-213 | 6h |
| TSE-602 | Implement GC (expired → grace → delete → audit) | internal/storage/gc/gc.go | TSE-201 | 4h |
| TSE-603 | Implement integrity scrubber (weekly re-hash) | internal/storage/gc/scrub.go | TSE-201 | 4h |
| TSE-604 | Time-to-live policy engine | internal/storage/gc/ttl.go | TSE-602 | 2h |

### Phase 7 Tasks (Snapshots + Observability)

| ID | Title | Files | Deps | Est. |
|----|-------|-------|------|------|
| TSE-701 | Implement snapshot create (quiesce → tar.zst → resume) | internal/storage/snapshot/create.go | TSE-301, TSE-101, TSE-201 | 6h |
| TSE-702 | Implement snapshot restore (extract → validate → resume) | internal/storage/snapshot/restore.go | TSE-701 | 4h |
| TSE-703 | Implement Prometheus metrics | internal/storage/metrics/metrics.go | All | 3h |
| TSE-704 | Implement admin CLI commands (trace tse status/flush/inspect) | internal/storage/admin/commands.go | All | 4h |
| TSE-705 | Implement full end-to-end test (ingest → flush → query → compact → GC → snapshot → restore) | internal/storage/e2e_test.go | All | 6h |

---

## 7. Parallel Development Plan

### Phase 0 (Week 1)
- Developer A: TSE-001, TSE-002 (data models + interfaces)
- Developer A → TSE-003, TSE-004 (Queue)
- Developer B: TSE-005, TSE-006 (Batch Writer + Writer Goroutine)
- Developer B (after Queue): TSE-007 (config), TSE-008 (crash harness)
- Developer C: TSE-009 (benchmark harness)

### Phase 1 + 2 (Weeks 2-3) — MAXIMUM PARALLELISM
- Developer A: TSE-101, TSE-102, TSE-104 (SQLite hot store + reader)
- Developer B: TSE-201, TSE-202, TSE-203, TSE-204, TSE-205 (Manifest — no deps on SQLite)
- Developer C: TSE-211, TSE-212, TSE-213, TSE-214 (Parquet Writer — depends only on Manifest)
- Developer D: TSE-215 (Parquet Reader — depends only on Manifest)

**Sync point at end of Week 2:** Manifest is done. SQLite hot store and Parquet Writer are done. Integration testing begins.

### Phase 3 (Week 4)
- Developer A: TSE-301, TSE-302 (Flusher — joins SQLite + Manifest + Parquet)
- Developer B: TSE-303, TSE-304 (Crash tests + retention — joins Flusher)
- Developer C: TSE-107 (SQLite soak test)

### Phase 4 (Week 5)
- Developer A: TSE-401, TSE-403, TSE-404 (Router + pagination)
- Developer B: TSE-402, TSE-405 (Cold reader + partial results)
- Developer C: TSE-406 (Integration tests)

### Phase 5 (Week 6)
- Single developer: TSE-501, TSE-502, TSE-503 (DuckDB — isolated component)

### Phase 6 (Week 7)
- Developer A: TSE-601 (Compactor)
- Developer B: TSE-602, TSE-603, TSE-604 (GC + Scrub + TTL)

### Phase 7 (Week 8)
- Developer A: TSE-701, TSE-702 (Snapshots)
- Developer B: TSE-703, TSE-704, TSE-705 (Metrics, Admin, E2E)

---

## 8. Interface Implementation Order

| Order | Interface | Reason |
|-------|-----------|--------|
| 1 | Writer | Every storage component depends on this. WriteBatch is the universal ingestion primitive. |
| 2 | Reader | Every query path depends on this. Must exist before Router or ColdReader. |
| 3 | Retention | Simple interface, needed by all lifecycle management. |
| 4 | ColdReader | Needed by Router. Implemented as pure-Go ParquetReader first, DuckDB second. |
| 5 | Flusher | Depends on Writer (SQLite/Parquet) + Manifest. Built after concrete stores exist. |
| 6 | Compactor | Depends on Reader + Writer + Manifest. Built after all stores exist. |

---

## 9. Data Models

### Core Event Model

```go
type Event struct {
    ID          string            `json:"id"`
    TenantID    string            `json:"tenant_id"`
    AgentID     string            `json:"agent_id"`
    Timestamp   int64             `json:"ts_us"`         // epoch microseconds
    IngestedAt  int64             `json:"ingested_at"`   // epoch microseconds
    EventType   string            `json:"event_type"`
    Severity    int               `json:"severity"`
    ProcessName string            `json:"process_name,omitempty"`
    Cmdline     string            `json:"cmdline,omitempty"`
    ParentPID   int               `json:"parent_pid,omitempty"`
    SHA256      string            `json:"sha256,omitempty"`
    DestIP      string            `json:"dest_ip,omitempty"`
    SrcIP       string            `json:"src_ip,omitempty"`
    UserName    string            `json:"user_name,omitempty"`
    Hostname    string            `json:"hostname,omitempty"`
    DataRaw     []byte            `json:"data_raw,omitempty"`
    Annotations map[string]string `json:"annotations,omitempty"`
}
```

### Query Model

```go
type Query struct {
    TenantID    string
    AgentIDs    []string
    EventTypes  []string
    MinSeverity int
    SinceUs     int64          // epoch microseconds
    UntilUs     int64
    Limit       int
    Cursor      string         // UUIDv7 continuation token
    OrderAsc    bool
}
```

### Result Model

```go
type Result struct {
    Events   []*Event
    Warnings []string
    Cursor   string    // last UUIDv7 in this page
    Total    int       // total matching (if computed)
}
```

### Parquet File Record (Manifest)

```go
type ParquetFileRecord struct {
    FileID           string `json:"file_id"`
    Path             string `json:"path"`
    TenantID         string `json:"tenant_id"`
    Level            int    `json:"level"`              // 0=hourly, 1=daily
    MinTimestampUs   int64  `json:"min_ts_us"`
    MaxTimestampUs   int64  `json:"max_ts_us"`
    MinEventID       string `json:"min_event_id"`
    MaxEventID       string `json:"max_event_id"`
    RowCount         int    `json:"row_count"`
    CompressedSize   int64  `json:"compressed_size"`
    UncompressedSize int64  `json:"uncompressed_size"`
    SHA256           string `json:"sha256"`
    Compression      string `json:"compression"`
    SchemaVersion    int    `json:"schema_version"`
    Status           string `json:"status"`   // writing, committed, superseded, expired, corrupted, deleted
    CreatedAt        int64  `json:"created_at"`
    UpdatedAt        int64  `json:"updated_at"`
}
```

### Watermark

```go
type Watermark struct {
    LastID    string `json:"last_id"`     // UUIDv7
    LastTS    int64  `json:"last_ts_us"`  // epoch microseconds
    UpdatedAt int64  `json:"updated_at"`
}
```

### FileInfo (Router/Reader)

```go
type FileInfo struct {
    Path   string `json:"path"`
    FileID string `json:"file_id"`
    Status string `json:"status"`
    MinTS  int64  `json:"min_ts_us"`
    MaxTS  int64  `json:"max_ts_us"`
}
```

### Compression Codec

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

### Config

```go
type Config struct {
    StoragePath   string            // local: /data/tse/ or s3://bucket/
   Compression   CompressionCodec  // default: zstd
    QueueCapacity int               // default: 65536
    BatchSize     int               // default: 1000
    BatchTimeout  time.Duration     // default: 250ms
    HotWindow     time.Duration     // default: 2h
    FlushInterval time.Duration     // default: 30s
    ColdTTL       time.Duration     // default: 365d
    GCInterval    time.Duration     // default: 24h
    ScrubInterval time.Duration     // default: 168h (weekly)
}
```

---

## 10. Testing Roadmap

### Phase 0 Tests
| Type | Target | Success |
|------|--------|---------|
| Unit | Queue enqueue/dequeue | 50K ops/sec, zero drops below capacity |
| Unit | Queue spill + drain | Spill written, drained when queue recovers |
| Unit | BatchWriter accumulation | 1000 events or 250ms, whichever first |
| Crash | Harness skeleton | kill -9, verify no corrupted committed data |

### Phase 1 Tests
| Type | Target | Success |
|------|--------|---------|
| Unit | SQLite hourly table CREATE/DROP | Table created, DROP TABLE works |
| Unit | Batched INSERT throughput | 50K events/sec sustained |
| Unit | HotReader UNION ALL queries | Correct results across 3 hourly tables |
| Integration | 24h soak at 50K/s | Zero errors, WAL size bounded |
| Concurrency | Writer + reader pool | No deadlocks, WAL checkpoint doesn't block writers |

### Phase 2 Tests
| Type | Target | Success |
|------|--------|---------|
| Unit | Manifest transactions | Atomic INSERT file + UPDATE watermark |
| Unit | ParquetWriter valid output | parquet-tools validate passes |
| Unit | Parquet compression ratio | >= 8x on real EDR data |
| Unit | Orphan GC | Temp files deleted on startup |
| Benchmark | Parquet write throughput | >= 50K events/sec |
| Benchmark | Compression ratio by codec | ZSTD vs Snappy vs LZ4 vs Brotli |

### Phase 3 Tests
| Type | Target | Success |
|------|--------|---------|
| Crash | Flusher at 1000 random kill points | Zero committed-data loss, zero duplicates |
| Integration | Full hot→cold pipeline | Watermark age < 90s at 50K/s |
| Integration | Retention DROP TABLE | Tables dropped only when fully behind watermark |
| Benchmark | Flush throughput | 100K rows/sec SQLite read + Parquet write |

### Phase 4 Tests
| Type | Target | Success |
|------|--------|---------|
| Unit | Router boundary merge | Zero duplicates, zero missing across boundary |
| Unit | Cursor pagination | Consistent pages under concurrent writes |
| Integration | Router + cold reader + hot reader | Full time range queries correct |
| Crash | Router + flusher concurrent | No partial results with missing data |
| Benchmark | Cold query (30d) | < 2s pure-Go, < 100ms DuckDB |

### Phase 5 Tests
| Type | Target | Success |
|------|--------|---------|
| Unit | DuckDB query results == pure-Go results | Same Parquet files, same results |
| Integration | DuckDB build tag | go build -tags duckdb works on 5 platforms |
| Benchmark | DuckDB cold query speed | 5-10x faster than pure-Go |

### Phase 6 Tests
| Type | Target | Success |
|------|--------|---------|
| Unit | Compactor atomic swap | Queries during compaction return correct results |
| Unit | GC audit trail | Deleted files recorded with timestamp |
| Unit | Scrub detection | Corrupted file detected and quarantined |
| Integration | Full lifecycle | Ingest → flush → compact → GC → verify |

### Phase 7 Tests
| Type | Target | Success |
|------|--------|---------|
| Integration | Snapshot create + restore | Exact state recovery |
| E2E | Full pipeline | Ingest 10M events → flush → query → compact → GC → snapshot → restore → verify |
| Load | 50K/s for 24h | Zero drops, zero errors, watermark < 90s |

---

## 11. Benchmark Roadmap

| Benchmark | Target | Phase |
|-----------|--------|-------|
| Queue throughput | 50K enqueue/sec, no drops | 0 |
| Queue spill throughput | 10K spill/sec to disk | 0 |
| SQLite hot ingest | 50K events/sec sustained | 1 |
| SQLite hot query (1h, 1 agent) | < 50ms | 1 |
| SQLite WAL size (24h soak) | < 1GB | 1 |
| Parquet write throughput | 50K events/sec | 2 |
| Parquet compression ratio | >= 8x real data, >= 15x synthetic | 2 |
| Parquet file target accuracy | 256MB ± 25% | 2 |
| Manifest lookup (1M files) | < 10ms | 2 |
| Flush latency (watermark age) | < 90s steady state | 3 |
| Crash recovery | 1000 iterations, zero loss | 3 |
| Router boundary merge | Zero duplicates, zero missing | 4 |
| Cold query (30d, pure-Go) | < 2s | 4 |
| Cold query (30d, DuckDB) | < 100ms | 5 |
| Compaction throughput | 256MB every 10s | 6 |
| GC scan (10K files) | < 5s | 6 |
| Scrub (1TB Parquet) | < 1h (low priority) | 6 |
| Snapshot create (100GB) | < 5 min | 7 |
| Snapshot restore (100GB) | < 10 min | 7 |
| Memory usage (steady state) | < 1GB RSS | All |
| Startup time | < 5s | All |
| Disk usage overhead (manifest) | < 1% of data size | All |

---

## 12. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| SQLite WAL grows unbounded | Low | Medium | Passive checkpoint goroutine, 1MB WAL target |
| ParquetWriter runs OOM on large sort | Low | High | Sort in streaming batches, not in memory |
| Flusher falls behind ingest | Medium | High | Alert at 15 min watermark age, scale writer |
| Late events cause partition bloat | Medium | Low | Straggler files merged by compactor |
| Manifest transaction deadlock | Low | High | Single writer goroutine for manifest |
| S3 latency for cold queries | Medium | Medium | Local caching layer (future) |
| Schema migration breaks old Parquet | Low | High | Schema version in each file, backward compat reader |
| High-cardinality agent_id column | Medium | Low | Dictionary encoding handles it; worst case → more storage |
| Disk full during flush | Low | High | Flusher stalls, watermark freezes, ingest keeps working |
| Power failure mid-flush | Medium | Low | Watermark + orphan GC proven under crash injection |
| DuckDB CGO breaks cross-compile | Low | Medium | Build tag isolates CGO; default build unaffected |

---

## 13. GitHub Milestones

### Milestone 1: Core Pipeline (Weeks 1-2)
**Objectives:** Queue, Batch Writer, Writer Goroutine, SQLite Hot Store, Manifest
**Issues:** TSE-001 through TSE-107, TSE-201 through TSE-205
**Completion criteria:** 50K/s ingest into SQLite hot tables, manifest operational, crash-injection harness running

### Milestone 2: Parquet + Flusher (Weeks 3-4)
**Objectives:** ParquetWriter, ParquetReader, Flusher, Retention
**Issues:** TSE-211 through TSE-215, TSE-301 through TSE-304
**Completion criteria:** Exactly-once hot→cold pipeline, watermark < 90s, crash recovery proven

### Milestone 3: Query + Cold Reader (Week 5)
**Objectives:** Router, ColdReader, pagination, partial results
**Issues:** TSE-401 through TSE-406
**Completion criteria:** Full time-range queries, boundary correctness, cursor pagination

### Milestone 4: DuckDB + Compactor (Week 6-7)
**Objectives:** DuckDB adapter, Compactor, GC, Scrub
**Issues:** TSE-501 through TSE-503, TSE-601 through TSE-604
**Completion criteria:** DuckDB query 5-10x faster, compaction atomic, bit rot detection

### Milestone 5: Production Readiness (Week 8)
**Objectives:** Snapshots, Metrics, Admin CLI, E2E tests
**Issues:** TSE-701 through TSE-705
**Completion criteria:** All benchmarks pass, 24h soak clean, snapshot + restore verified

---

## 14. Recommended Build Order

1. **Interfaces + Data Models** — Everything depends on these. Build first, change rarely.
2. **Manifest** — Zero dependencies. Needed by every downstream component.
3. **Queue + Batch Writer + Writer Goroutine** — Ingest pipeline, no storage needed yet.
4. **SQLite Hot Store** — Production storage for the hot tier.
5. **Parquet Writer** — Production storage for the cold tier. Depends only on Manifest.
6. **Flusher** — Joins SQLite + Manifest + Parquet. The most complex single component.
7. **Parquet Reader (pure-Go)** — Cold query path. Depends on Manifest.
8. **Router** — Joins SQLite + ColdReader + Manifest. Query path.
9. **DuckDB Adapter** — Optional performance upgrade. Depends on Router interfaces.
10. **Compactor** — Operational. Depends on Manifest + Parquet Reader/Writer.
11. **GC + Scrub** — Operational. Depends on Manifest.
12. **Snapshots** — Operational. Depends on everything.
13. **Metrics + Admin** — Polish. Depends on everything.

---

## 15. Definition of Done

**Performance:**
- [ ] 50K events/sec sustained ingest over 24h soak
- [ ] p99 enqueue latency < 50ms
- [ ] Flush watermark age < 90s steady state
- [ ] Hot query (1h, 1 agent) < 50ms
- [ ] Cold query (30d, 1 tenant) < 2s (pure-Go) / < 100ms (DuckDB)
- [ ] Compression >= 10x on real EDR payloads

**Reliability:**
- [ ] Crash recovery proven: 1000 kill -9 iterations with zero committed-data loss
- [ ] Boundary queries return zero missing, zero duplicate events
- [ ] Retention DROP TABLE never deletes unflushed data
- [ ] Orphan GC cleans up temp files on every startup

**Documentation:**
- [ ] All exported types documented
- [ ] Configuration reference with defaults
- [ ] Deployment guide (single SOC + enterprise multi-SOC)
- [ ] Admin commands reference

**Testing:**
- [ ] Unit test coverage >= 80% for all storage packages
- [ ] Integration tests for every phase boundary
- [ ] Crash-injection harness running in CI
- [ ] 24h soak test passing

**Benchmarks:**
- [ ] All benchmark targets met
- [ ] Benchmarks in CI (regression detection)

**Recovery:**
- [ ] Snapshot create/restore verified end-to-end
- [ ] Startup orphan GC tested with orphan files
- [ ] Corrupted file detection and quarantine tested

**Observability:**
- [ ] Prometheus metrics for all key operations
- [ ] Watermark age alert threshold configurable
- [ ] Drop counter alert

**Deployment:**
- [ ] Default go build produces CGO-free binary
- [ ] go build -tags duckdb produces DuckDB-enabled binary
- [ ] Build passes on linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64
- [ ] S3 configuration tested with MinIO (local S3 mock)
