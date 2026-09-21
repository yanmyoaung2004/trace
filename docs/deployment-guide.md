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

## S3 Cold Storage

Instead of storing Parquet files locally, write them to S3/MinIO:

```bash
trace serve --tse \
  --tse-s3-bucket trace-events \
  --tse-s3-endpoint minio:9000 \
  --tse-s3-region us-east-1

# Or set in ~/.trace/config.json:
#   "tse_s3_bucket": "trace-events",
#   "tse_s3_endpoint": "minio:9000",
#   "tse_s3_region": "us-east-1"
```

The S3 client is a lightweight HTTP client (no AWS SDK dependency). Works with MinIO, AWS S3, or any S3-compatible storage.

**How it works:**
1. ParquetWriter writes to local temp file (fast)
2. Uploads to `s3://bucket/events/{tenant}/{date}/{hour}/part-*.parquet`
3. Manifest stores the `s3://` path
4. Cold reader downloads from S3 to temp on first read, caches locally

## Storage Layout

```
~/.trace/
  config.json          # Main configuration
  trace.db             # Investigations, cases, hunts
  tse/
    hot.db             # Recent events (SQLite WAL)
    manifest.db         # Parquet file catalog + watermark
    events/             # Parquet files (local, or s3:// remote)
      {tenant}/{date}/{hour}/
        part-*.parquet
    temp/               # Temp files during parquet writes
    spill/              # Queue spill-over when backlogged
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

## TLS / HTTPS

```bash
# Using existing certificate
trace server --http-addr :443 --tls-cert /etc/certs/cert.pem --tls-key /etc/certs/key.pem

# Generate self-signed cert (for testing)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 365 -nodes -keyout key.pem -out cert.pem \
  -subj "/CN=localhost"
trace server --tls-cert cert.pem --tls-key key.pem
```

The `trace server` command automatically uses HTTPS when `--tls-cert` and `--tls-key` are provided. Without these flags, it falls back to plain HTTP.

### TLS-auto (self-signed) + plaintext-refuse

The only TLS-terminating listener is `trace server` (ServeHTTP via
`server.RunServer`). The `trace serve` daemon starts no HTTP listener of
its own — its `--export` report server is plaintext-only HTTP, and
`--server-addr` is an edge-sync client — so its `--tls-*` flags only
materialise a pair for later `server` use:

```bash
# Auto-generate a genkey-equivalent self-signed pair into ~/.trace/tls/
# (dir 0700, cert.pem 0644, key.pem 0600 + Chmod) and serve HTTPS with it:
trace server --tls-auto

# Reuse the existing pair on the next boot (no regeneration):
trace server --tls-auto

# Fail closed instead of serving plaintext HTTP (default: warn and serve HTTP):
trace server --tls-require --tls-auto

# Explicit cert/key still wins over --tls-auto:
trace server --tls-cert /etc/certs/cert.pem --tls-key /etc/certs/key.pem

# Daemon: pre-generate the same pair for a later `server` invocation:
trace serve --tls-auto
# Daemon: refuse the plaintext-only --export report server:
trace serve --export :8080 --tls-require   # exits non-zero, refuses plaintext
```

Permissions: `~/.trace/tls/` is created `0700`, `cert.pem` is written
`0644`, `key.pem` is written `0600` and re-`Chmod`ed to `0600` even when
the file pre-existed (same logic as `trace genkey`). Verify:

```bash
stat -c '%a %n' ~/.trace/tls ~/.trace/tls/cert.pem ~/.trace/tls/key.pem
# expect: 700 .../tls, 644 .../cert.pem, 600 .../key.pem

# HTTPS serves the dashboard/API; -k trusts the self-signed cert:
curl -k https://localhost:8080/healthz
# expect: ok
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

### Update signing ceremony (agent self-update + installers)

Server signs the published `(version, sha256)` binding with the ed25519
private key in `TRACE_UPDATE_SIGNING_KEY` (base64 32-byte seed or 64-byte
private key) and dual-publishes it: as `"signature"` in the update-check
JSON (the agent's trust root) and as `X-Trace-Signature` on the download
response (installers verify before chmod; `X-Trace-SHA256` always ships).
Agents verify with `TRACE_UPDATE_VERIFY_KEY_HEX` (32-byte hex public key,
provisioned offline -- never from the network).

Ceremony steps (operator-side; ceremony never generates production keys for you):

1. Generate ed25519 offline; keep the private key off the fleet:
   `trace update-keys gen --out /safe/offline/update-seed.b64` (seed file
   written mode 0600, private seed never printed) or `trace update-keys gen`
   to print the base64 seed exactly once plus the hex public key.
2. Set `TRACE_UPDATE_SIGNING_KEY` on the server only (from the offline seed).
3. Publish the hex public key to agents as
   `TRACE_UPDATE_VERIFY_KEY_HEX` (agent config or env).
4. Publish sidecars for the release dir (`.sha256` = hex digest,
   `.sig` = base64 ed25519 over the raw 32-byte digest, matching
   `internal/server/update_sign.go` + `internal/edr_agent/updater`):
   `trace update-keys publish --dir ./release/`.
5. Check the release locally, fail-closed on missing/mismatch:
   `trace update-keys verify --dir ./release/ --verify-key <hex-pubkey>`.
6. Dual-publish `.sha256` + `.sig` for one release unsigned-tolerant
   (unkeyed fleets warn, never refuse).
7. Then enforce: agents with a verify key fail closed -- unsigned,
   tampered, or downgraded (non-semver-newer over HTTPS, same-origin)
   updates are refused, never installed.

## Compatibility

| Component | Requires | Notes |
|-----------|----------|-------|
| Core | Go 1.26+ | Pure Go, no CGO needed |
| DuckDB reader | CGO, GCC | 5-10x faster cold queries |
| ETW (Windows) | Windows 10+ | EDR agent on Windows |
| Wazuh rules | 464 built-in | Rule converter in tools/ |

## Agent enrollment (provision-token only)

First-time agent enrollment requires a one-time provision token minted by an
admin. The server consumes the token, assigns the org, and returns the
agent's API key (persisted 0600 in `<data_dir>/agent.json` with the agent
id). The key then auths heartbeat/events/actions — it is never sent on the
enroll path, and client-minted `--api-key` values on enroll are rejected.
See the `trace-agent` flags in `docs/cli-reference.md` and the Custom EDR
Agent section in `docs/user-guide.md`.

```bash
# 1. Admin mints a one-time token for the org
trace admin token mint --org <org-id>

# 2. Enroll the agent with the token (flag, env, or config file)
TRACE_AGENT_SERVER="https://trace-server:8080" \
TRACE_AGENT_PROVISION_TOKEN="<token-from-admin>" \
trace-agent

# 3. Verify
trace edr list
```

Kubernetes: enroll out-of-band, then place the server-issued key in the
`trace-agent-key` Secret (`deploy/daemonset.yaml` mounts it via
`TRACE_AGENT_API_KEY_FILE`). Never commit a key — the manifest placeholder
must be replaced before applying.

## DaemonSet image digest pinning

`deploy/daemonset.yaml` ships with a failing-closed placeholder digest
(`@sha256:0000...`) and MUST NOT be applied as-is. Never invent or
hand-type a digest — pin tag+digest together after the first tagged push:

```bash
TAG=v0.1.1
DIGEST=$(crane digest ghcr.io/yanmyoaung2004/trace-agent:${TAG})
scripts/pin-digest.sh "${TAG}" "${DIGEST}"
```

The script verifies the digest shape (`sha256:` + 64 lowercase hex),
rewrites the `image:` line keeping tag+digest together, and fails if any
zero placeholder remains on an image line. Verify:

```bash
grep 'image:' deploy/daemonset.yaml
crane digest ghcr.io/yanmyoaung2004/trace-agent:${TAG}  # must match
```
