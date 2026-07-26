# Upgrade Guide

## v0.1.0 → v0.1.1 (TSE Release)

**Changes:**
- New: Trace Storage Engine (SQLite hot tier + Parquet cold tier)
- New: DuckDB analytics (optional, requires CGO)
- New: Prometheus /metrics endpoint
- New: Multi-node leader election (S3-based)
- New: S3 cold storage support
- Improved: Test coverage 59% → 100%
- Improved: All packages race-free
- Fixed: 8 bugs (slice panics, config validation, disk full handling, etc.)

**Upgrade steps:**

```bash
# 1. Backup your data
trace tse snapshot --storage-path ~/.trace/tse -o pre-upgrade-backup.tar.gz
cp ~/.trace/config.json ~/.trace/config.json.v011

# 2. Replace binary
cp trace /usr/local/bin/trace

# 3. Verify
trace version
trace tse status --storage-path ~/.trace/tse

# 4. Start with new features
trace serve --tse --siem
```

**Config changes (v0.1.1):**

```json
{
  "tse": {
    "enabled": true,
    "storage_path": "~/.trace/tse",
    "compression": "zstd",
    "cold_ttl": "8760h"
  }
}
```

**Breaking changes:**
- Config JSON now rejects unknown keys (typo `compresion` will error)
- TSE requires `trace serve --tse` flag (not enabled by default)
- `trace tse status` now requires `--storage-path` or a running server

**Rollback:**

```bash
# Restore old binary
cp /usr/local/bin/trace.v010 /usr/local/bin/trace

# Restore old config
cp ~/.trace/config.json.v011 ~/.trace/config.json
```

## v0.1.1 → v0.1.2

**Changes:**
- New: Graceful shutdown (Flusher.Stop with 30s timeout)
- New: Rate limiting (IngestQueue with spill-to-disk)
- New: TLS support (--tls-cert/--tls-key flags)
- New: Web UI dashboard (TSE widget, SIEM alerts page, create case form)
- New: S3 cold storage (--tse-s3-bucket flag)
- New: LLM dispatch improvements (cache, provider chaining, progress callback)
- Improved: Web dashboard with alerts page and active nav
- Improved: 14 packages gained tests (70+ new tests)
- Fixed: 6 gaps closed

**Config changes (v0.1.2):**

```json
{
  "tse": {
    "s3_bucket": "trace-events",
    "s3_endpoint": "minio:9000"
  }
}
```

No breaking changes from v0.1.1.
