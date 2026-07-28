# Scaling Plan: Multi-node, 5M+ ev/s, Automated Backup

## Overview

Three interconnected problems to solve in sequence:

| Problem | Current | Target | Approach |
|---------|---------|--------|----------|
| **No backup** | Manual snapshot only | Automatic S3 backup with PITR | WAL archiving + periodic snapshot to S3 |
| **SQLite scaling ceiling** | 500K ev/s single node | 5M+ ev/s across N shards | Consistent-hash sharding + fan-out query |
| **Single-process server** | One process, one point of failure | N stateless servers behind LB | External DB backend, shared-nothing server layer |

---

## Phase 1: Automated Backup (3-5 days)

### 1.1 TSE snapshot scheduler
- **What**: Background goroutine that calls `snapshot.Create()` every N hours
- **Config**: `--tse-backup-interval 6h --tse-backup-dir /mnt/backup`
- **S3 target**: Upload snapshot tarball to S3 bucket
- **Output**: `tse-snapshot-{timestamp}.tar.gz` containing hot.db + manifest.db + parquet/ + spill/

### 1.2 Server DB backup
- **What**: Periodic SQLite backup of `trace.db` (the server's metadata DB)
- **Method**: `sqlite3 .backup` or `VACUUM INTO` for safe online backup
- **S3 target**: Upload to `s3://backups/server/{timestamp}/trace.db`

### 1.3 WAL archiving for PITR
- **What**: Copy WAL files to S3 before checkpoint removes them
- **Integration**: Hook into `checkpointer` (already exists in sqlite/hot_store.go)
- **Restore**: Script to download WAL chain + snapshot, replay to point-in-time

### 1.4 Recovery CLI
- **What**: `trace tse recover --from s3://backups/tse-snapshot-*.tar.gz`
- **Behavior**: Download snapshot, extract, apply WAL archives up to specified time

---

## Phase 2: Sharded TSE (2 weeks)

### 2.1 Shard routing layer
- **What**: New `internal/storage/shard/` package
- **Router**: `consistentHash(tenantID + ":" + agentID) % numShards`
- **Write**: `ShardRouter.WriteEvents(ctx, events)` → routes each event to the correct shard
- **Read**: `ShardRouter.Query(ctx, query)` → fans out to all shards, merges+dedups results
- **Config**: `--tse-shard-count 4 --tse-shard-dir ./data/tse/shard-{n}`

### 2.2 Each shard is a full TSE instance
- Each shard has its own: SQLiteHotStore, Manifest, Flusher, ParquetWriter, ColdReader
- Shards are independent — no cross-shard communication
- Adding a shard = more write capacity (linear scaling)

### 2.3 Merge and dedup
- Query fan-out merges results from all shards
- Sort by timestamp, dedup by ID
- Pagination across shards (cursor-based)

### 2.4 Rebalancing (stretch goal)
- When `numShards` changes, rehash existing events
- Background process that migrates events between shard dirs
- Only needed when adding/removing shards

---

## Phase 3: Stateless Server (1 week)

### 3.1 External DB backend
- **Current**: Server uses local SQLite (`trace.db`) for users, investigations, cases, agents
- **Change**: Support PostgreSQL / MySQL via `database/sql` interface
- **Why**: Local SQLite prevents multiple server instances from sharing state

### 3.2 Stateless HTTP server
- Once the DB is external, `trace server` becomes stateless
- Multiple instances behind a load balancer (HAProxy, Nginx, or k8s Service)
- No sticky sessions needed — all state is in the external DB + TSE shards

### 3.3 Agent connection management
- Agents connect to load balancer, not a specific server
- Heartbeat/event/action endpoints work with any server instance
- Server-side action dispatch picks an available agent connection

### 3.4 Health check endpoint enhancement
- Add `/readyz` with dependency checks (DB reachable, TSE shards online)
- Load balancer uses this to route traffic only to healthy instances

---

## Effort Summary

| Phase | Duration | Dependencies | Risk |
|-------|----------|-------------|------|
| **1. Backup** | 3-5 days | None | Low |
| **2. Sharded TSE** | 2 weeks | Phase 1 | Medium (query merge complexity) |
| **3. Stateless Server** | 1 week | Phase 2 | Medium (DB migration, zero-downtime) |

**Total**: ~4 weeks for a fully scalable, backed-up, multi-node deployment.
