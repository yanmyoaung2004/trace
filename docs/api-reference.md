# Trace API Reference

## CLI Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `trace` | — | Launch TUI dashboard |
| `init` | — | First-run setup wizard |
| `serve` | — | Start daemon (SIEM, TSE, hunts, scheduler) |
| `server` | — | Start central server + web dashboard |
| `investigate` | `inv` | Run a security investigation |
| `status` | `st` | View investigation status |
| `history` | `hist` | List recent investigations |
| `report` | — | View investigation report |
| `case` | — | Manage cases (10 subcommands) |
| `hunt` | — | Manage threat hunts (6 subcommands) |
| `compliance` | — | Compliance scanning (4 subcommands) |
| `edr` | — | Manage EDR agents (5 subcommands) |
| `tse` | — | TSE management (status, flush, inspect, snapshot, metrics, config) |
| `approval` | — | HITL approval management |
| `plugin` | — | Plugin management (4 subcommands) |
| `genkey` | — | Generate TLS cert |
| `update` | — | Update binary, intel, or playbooks |
| `version` | — | Print version |

## HTTP API (trace server)

### Health

```
GET /healthz → 200 "ok"
GET /readyz → 200 "ok"
```

### Metrics

```
GET /metrics → Prometheus text format
```

### Dashboard

```
GET  /                      → Investigation list + search + filters
GET  /investigations/{id}   → Investigation detail with timeline
GET  /correlations           → Cross-node IOC correlations
GET  /cases                  → Case list + create form
POST /cases                  → Create case (form: title, severity, description)
GET  /alerts                 → SIEM alert timeline (query: ?severity=N)
GET  /api/live               → Live dashboard data (JSON)
GET  /api/tse                → TSE metrics (JSON)
```

### Sync API (edge nodes)

```
POST /api/v1/register         → Register edge node
POST /api/v1/heartbeat        → Node heartbeat
POST /api/v1/push             → Push investigation to central server
```

### Organization Management

```
GET  /api/orgs                → List orgs
POST /api/orgs                → Create org
GET  /api/users               → List users
POST /api/users               → Create user
```

## TSE CLI

```
# Status & monitoring
trace tse status --storage-path ~/.trace/tse
trace tse metrics
trace tse inspect --storage-path ~/.trace/tse

# Operations
trace tse flush                        # Force SQLite → Parquet flush
trace tse snapshot -o backup.tar.gz    # Full snapshot
trace tse config show                  # View config
trace tse config set retention.days 365d
trace tse config set compression snappy
```

## Flags (trace serve)

```
--siem                          Enable SIEM log monitoring
--tse                           Enable Trace Storage Engine
--tse-storage-path              TSE data directory
--tse-compression               Parquet compression (zstd, snappy, gzip, lz4, none)
--tse-compression-level         Compression level (0=default)
--tse-row-group-size            Parquet row group size
--tse-node-role                 Multi-node role (leader/follower/auto)
--tse-s3-bucket                 S3 bucket for Parquet files
--tse-s3-endpoint               S3/MinIO endpoint
--tse-s3-region                 S3 region
--syslog-addr                   Syslog listener address
--log-dir                       Log directories to watch
--export                        HTML report server address
--server-addr                   Central server address for edge sync
--tls-cert                      TLS certificate file
--tls-key                       TLS key file
--config                        Config file path
```

## Prometheus Metrics

```
trace_tse_events_enqueued_total
trace_tse_events_written_total
trace_tse_events_flushed_total
trace_tse_events_dropped_total
trace_tse_events_read_total
trace_tse_queue_depth
trace_tse_watermark_age_seconds
trace_tse_parquet_files_created_total
trace_tse_parquet_bytes_written_total
trace_tse_hot_table_count
trace_tse_cold_file_count
trace_tse_flush_errors_total
trace_tse_query_errors_total
trace_tse_disk_bytes_total
trace_tse_disk_bytes_free
trace_tse_disk_usage_ratio
```
