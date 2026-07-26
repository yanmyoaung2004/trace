# S3 Cold Storage + Multi-Node Plan

---

## Gap 2: S3 Cold Storage

**Goal:** Parquet writer and cold reader can use S3/MinIO as storage backend instead of local filesystem.

### Tasks

| # | Task | File(s) | Effort |
|---|------|---------|--------|
| 2.1 | Add `aws-sdk-go` dependency for S3 client | `go.mod` | 10min |
| 2.2 | Add config fields: `S3Bucket`, `S3Endpoint`, `S3Region`, `S3UseSSL` | `internal/config/config.go` | 30min |
| 2.3 | Add `--tse-s3-bucket`, `--tse-s3-endpoint`, `--tse-s3-region` flags | `cmd/trace/serve.go` | 30min |
| 2.4 | Create S3 writer in ParquetWriter (detect `s3://` prefix, upload after local write) | `internal/storage/parquet/writer.go` | 3h |
| 2.5 | Create S3 cold reader (download from S3 to temp, then read locally) | `internal/storage/cold/parquet_reader.go` | 2h |
| 2.6 | Wire S3 init in `tse_init.go` | `cmd/trace/tse_init.go` | 1h |
| 2.7 | Test: write → S3 read-back → verify SHA-256 | `internal/storage/harness/s3_test.go` | 2h |
| 2.8 | Update deployment guide with S3/MinIO config | `docs/deployment-guide.md` | 1h |

**Total: ~10h**

### Design

```
┌──────────────┐     ┌──────────────┐
│  WriteBatch   │     │  ColdReader  │
│  parquet file │     │  reads from  │
│  → local temp │     │  S3 → temp   │
│  → upload S3  │     │  → parse     │
│  → rename     │     │  → return    │
│  → SHA-256    │     └──────┬───────┘
└──────┬───────┘            │
       │                    │
       └────────┬───────────┘
                │
        ┌───────▼───────┐
        │    MinIO/S3    │
        │  (shared cold) │
        └───────────────┘
```

The Parquet writer writes to a local temp file as before, then uploads to S3. The manifest stores the `s3://` path. The cold reader downloads from S3 to a temp file on first read, caches locally.

### Implementation Sketch

```go
// internal/storage/parquet/writer.go
type S3Config struct {
    Bucket   string
    Endpoint string
    Region   string
    UseSSL   bool
}

func (w *ParquetWriter) writeBatchS3(ctx context.Context, events []*storage.Event, partitionKey string) (*storage.FileResult, error) {
    // 1. Write to local temp (same as before)
    // 2. Upload to s3://bucket/partitionKey/file.parquet
    // 3. Return s3:// path in FileResult
}
```

---

## Gap 6: Multi-Node Active-Passive

**Goal:** Two nodes can run in active-passive mode sharing S3 cold storage. If the leader dies, the follower takes over.

### Tasks

| # | Task | File(s) | Effort |
|---|------|---------|--------|
| 6.1 | Add leader election via heartbeat file in S3 | `internal/edge/client.go` | 4h |
| 6.2 | Add `--tse-node-role` flag (leader/follower/auto) | `cmd/trace/serve.go` | 1h |
| 6.3 | Follower disables flusher, only reads from S3 | `cmd/trace/tse_init.go` | 2h |
| 6.4 | Leader election: write heartbeat every 5s to `s3://bucket/.leader` | `internal/edge/client.go` | 2h |
| 6.5 | Follower watches heartbeat, promotes self if leader times out (>15s) | `internal/edge/client.go` | 3h |
| 6.6 | Add `--tse-failover-timeout` flag | `cmd/trace/serve.go` | 30min |
| 6.7 | Docker Compose with 2 nodes + MinIO | `docker-compose.yml` | 3h |
| 6.8 | Test: kill leader → follower picks up in <20s | `internal/storage/harness/multinode_test.go` | 3h |

**Total: ~18h**

### Design

```
Leader                     Follower
──────                     ────────
Flusher: ON                Flusher: OFF
Writes Parquet to S3       Reads Parquet from S3
Accepts events             Accepts events (writes to local hot)
Heartbeat every 5s         Watches heartbeat
  → writes s3://bucket/      → reads s3://bucket/
    .leader/ts                .leader/ts
                             If ts > 15s old:
                               become leader
                               start flusher
```

### Leader Election (Simplest Approach)

No Raft, no etcd. Just a heartbeat file in S3:

```
s3://trace-events/
  .leader/
    ts          # current epoch timestamp (written by leader every 5s)
    node_id     # which node holds the lease
  events/
    ...
```

The leader writes its timestamp to `s3://bucket/.leader/ts` every 5s. Followers read this file every 5s. If the timestamp is >15s old, the follower writes its own node_id to `.leader/node_id` and becomes the leader.

**Lease contention:** If two nodes both think they're leader, the one with the alphabetically smaller node_id wins (deterministic tiebreak).

### Why S3-first (not Raft)

S3 is already needed for Gap 2 (shared cold storage). S3-based leader election piggybacks on the same infrastructure — no separate consensus cluster needed. The trade-off is that leader election takes ~15s (vs ~5s for Raft), but that's acceptable for active-passive HA.

---

## Execution Order

```
Day 1-2: Gap 2 (S3) — writer → reader → test
Day 3-5: Gap 6 (Multi-node) — leader election → follower → docker compose → test
```

## Total: ~28h
