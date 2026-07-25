# Trace — Deployment Guide

## Quick Start

```bash
# Build
go build -o trace ./cmd/trace

# Initialize (creates ~/.trace/ with default config)
./trace init

# Start with SIEM + TSE
./trace serve --siem --tse
```

## Modes

| Mode | Command | Description |
|------|---------|-------------|
| **CLI only** | `trace investigate` | Interactive investigation without server |
| **Server** | `trace serve` | HTTP API + dashboard on :8080 |
| **SIEM** | `trace serve --siem` | Enable log monitoring (EVTX, syslog) |
| **TSE** | `trace serve --tse` | Enable columnar event storage |
| **EDR Agent** | `trace-agent` | Standalone endpoint agent |

## TSE Configuration

Set in `~/.trace/config.json` under `tse.*`:

```json
{
  "tse": {
    "enabled": true,
    "storage_path": "/var/lib/trace/tse",
    "compression": "zstd",
    "compression_level": 1,
    "row_group_size": 1000000,
    "hot_window": "2h",
    "flush_interval": "30s",
    "cold_ttl": "8760h"
  }
}
```

Or via CLI:

```bash
trace tse config set compression snappy
trace tse config set retention.days 720h
trace tse config set storage_path /mnt/large-disk/tse
trace tse config show
```

## Storage Layout

```
~/.trace/
  config.json          # Main configuration
  trace.db             # Investigations, cases, hunts
  tse/
    hot.db             # Recent events (SQLite WAL)
    manifest.db         # Parquet file catalog + watermark
    events/             # Parquet files (cold storage)
      {tenant}/{date}/{hour}/
        part-*.parquet
    temp/               # Temp files during parquet writes
```

## Disk Requirements

- **hot.db**: ~2GB max (2-hour window at 1000 events/sec)
- **manifest.db**: ~1GB per 100K parquet files
- **Parquet files**: ~1KB per event (compressed with ZSTD)

Minimum: 10GB free space. Writes rejected at 95% disk usage.

## Production Deployment

### Linux (systemd)

```
[Unit]
Description=Trace
After=network.target

[Service]
ExecStart=/usr/local/bin/trace serve --siem --tse
Restart=always
User=trace

[Install]
WantedBy=multi-user.target
```

### Docker

```bash
docker run -v /var/lib/trace:/root/.trace ghcr.io/yanmyoaung2004/trace serve --tse
```

### Windows Service

```powershell
# Install
trace-agent --install

# Uninstall
trace-agent --uninstall
```

## Monitoring

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Returns `ok` (200) |
| `GET /readyz` | Returns `ok` (200) |
| `GET /metrics` | Prometheus metrics (16 TSE counters + disk) |
| `GET /` | Dashboard HTML |

### Key Metrics

```
trace_tse_events_written_total
trace_tse_events_flushed_total
trace_tse_events_dropped_total
trace_tse_flush_errors_total
trace_tse_queue_depth
trace_tse_disk_bytes_free
trace_tse_watermark_age_seconds
```

## Backup

```bash
# Snapshot TSE state (hot + cold + manifest)
trace tse snapshot --storage-path /var/lib/trace/tse -o backup.tar.gz

# Manual backup (shutdown first)
cp -a ~/.trace ~/backups/trace-$(date +%Y%m%d)
```

## Upgrade

```bash
# Backup first
trace tse snapshot --storage-path ~/.trace/tse

# Replace binary
cp trace /usr/local/bin/trace

# Restart
systemctl restart trace

# Verify
trace version
trace tse status --storage-path ~/.trace/tse
```

## Compatibility

| Component | Requires | Notes |
|-----------|----------|-------|
| Core | Go 1.26+ | Pure Go, no CGO needed |
| DuckDB reader | CGO, GCC | 5-10x faster cold queries |
| ETW (Windows) | Windows 10+ | EDR agent on Windows |
| Wazuh rules | 464 built-in | Rule converter in tools/ |
