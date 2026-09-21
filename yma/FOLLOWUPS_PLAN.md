# Follow-ups Execution Plan (F1–F7 + Fleet + Phase 4)

> Source: `yma/FIX_PLAN.md` Completion Log + open follow-ups F1–F7, fleet enroll blocker, Phase 4 remainder.
> Date: 2026-09-21. Code root `dev/`. Rule: modular monolith stays; one commit per problem area by Main; agents leave files dirty, no self-commit.

## Order (parallel where safe, serial where shared)

```text
Wave A (parallel): Fleet enroll | Supply hygiene (F1/F2/F3) | Signing ceremony (F4) |
                   Compactor Tx (F5) | Disk+backup+gates (F6) |
                   Detection hygiene (F7) | Phase 4 product
Wave B (Main): build + vet + short suite + closure greps + per-area commits
```

Shared-file protocol: exclusive ownership below; cross-owner touch requires `hub send` before editing + ack. Main reconciles integration (siem breakage precedent).

## Workstreams

### W0 Fleet enroll unblock (P0, blocks fleet use)
- Own: `internal/edr_agent/transport/client.go` (`RegisterRequest`), `internal/edr_agent/agent.go` (`register`), `internal/edr_agent/config.go`, `cmd/trace-agent/main.go` (+ tests).
- Change: add `provision_token` field; `--provision-token` flag + `TRACE_AGENT_PROVISION_TOKEN` env + config file key; send in register; reject client `api_key` (server already 400s it); persist returned `agent_id`/`api_key` 0600; update `agent_integration_test.go` stubs to provision-token shape.
- Accept: `trace-agent --provision-token <tok>` enrolls against real server; wrong/missing token = 401 with clear message; no `api_key` sent on enroll.

### W1 Supply hygiene (F1/F2/F3)
- Own: `deploy/daemonset.yaml`, `docker-compose.yml`, `Dockerfile`, `deploy/Dockerfile.agent`, `tools/wazuh-converter/*`, `go.mod`/`go.sum`.
- Change: F1 — replace `:latest` with pinned immutable tags (+ digest comment; real ghcr digest after first tagged push, script/document replacement); F2 — compute reviewed hashes into `tools/wazuh-converter/ruleset.lock`, `-verify` enforces; F3 — `go mod tidy` (promote `golang.org/x/mod`), verify build.
- Accept: no `:latest`/`0000` unmarked; converter `-verify` green; `go build ./...` green.

### W2 Signing ceremony (F4)
- Own: `internal/edr_agent/updater/*`, `internal/server/update_sign.go` + `admin.go` signing section, `deploy/install.sh|ps1` verify path, docs.
- Change: server `TRACE_UPDATE_SIGNING_KEY` (ed25519, base64) signs `(version+sha)`; agent `TRACE_UPDATE_VERIFY_KEY_HEX` verifies; dual-publish `.sha256` + `.sig` one release; fail-closed when keyed-but-absent; semver compare; HTTPS-only; installer verifies both before chmod.
- Accept: unsigned/tampered/downgraded update refused; signed happy-path passes; docs state ceremony steps.

### W3 Compactor Tx restore (F5)
- Own: `internal/storage/compactor/*`, `internal/storage/manifest/*` (Tx variants only).
- Change: restore group-commit to single `Transaction` with `AddFileTx`/`UpdateFileStatusTx`; root-cause the parser failure (suspect edit-tool artifact, file itself is valid Go); keep straight-line version as fallback behind comment if parser blocks; crash-during-compact test.
- Accept: compact path atomic (daily insert + supersede in one tx); crash test green; `go test ./internal/storage/compactor/` green.

### W4 Disk + backup + gates (F6)
- Own: `internal/storage/backup/*`, `cmd/trace/tse_init.go`, `cmd/trace/tse_cmd.go`, `internal/storage/disk*`.
- Change: disk-full enforce 95% (warn 85%) wired into ingest (not log-only); backup streaming (no whole-file `ReadFile`) + filtered `tse-snapshot-*.tar.gz` rotation; run kill-9/soak/stress/malware/e2e + DuckDB CGO where possible, or report environment blockers.
- Accept: writes rejected at 95% with metric; large snapshot restore drill passes; gate results recorded.

### W5 Detection hygiene (F7)
- Own: `internal/sift/*` (incl `hash.go` dup delete), `intel/seed-iocs.json` (new single store), `internal/edr_agent/monitor/yara.go|correlator*`, `internal/integration/{abuseipdb,otx}/*` + notifier/splunk/elastic creds path, fuzz tests.
- Change: delete `sift/hash.go` dup → single intel store (`seed-iocs.json`, exact+CIDR, no substring FP); TI creds from central config (not LLM params); ReDoS/malformed-YAML fuzz; 429/500/truncated-timeout/cache integration tests; wire splunk/elastic connector/breaker fields.
- Accept: conflicting-verdict dup gone; creds never from LLM params; new fuzz + table tests green.

### W6 Phase 4 product (asset/risk/reporting/correlation)
- Own (new, additive only): `internal/asset/*` (inventory + vuln join + risk scoring), `internal/compliance/*` reporting extensions, `internal/cases/*` read-only consumers (coordinate), dashboard read-only panels (coordinate via hub).
- Change (minimal viable, additive): asset type + `risk_score`, vuln join feeding triage; scheduled reporting + CSV/CEF exports (alongside existing HTML/PDF); entity correlation graph (host/user/process/ip) behind existing tables; no schema drops.
- Accept: asset→vuln→risk visible in triage; scheduled + CSV/CEF export works; correlation beyond IOC-counts demonstrated.

## Verification (Main, Wave B)
- `CGO_ENABLED=0 go build ./...`, `go vet ./...` (expect only pre-existing ETW note), `go test ./... -short -count=1 -p 2` zero FAIL.
- Closure greps: `sh -c` variable-input zero; `OR org_id` zero; `synchronous=OFF` zero; `InsecureSkipVerify` zero; `:latest`/`CHANGE_ME`/`tracetrace` zero (outside docs history).
- Commit per area by Main only. Agents report `files_changed` + scoped verification, no `git commit`.
