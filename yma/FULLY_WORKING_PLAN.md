# FULLY-WORKING Plan — close every remaining blocker with evidence

> Date: 2026-09-21. Code root `dev/`. Parents: `yma/AUDIT.md`, `yma/FIX_PLAN.md` (+Wave A log), `yma/FOLLOWUPS_PLAN.md`, `yma/STATUS_AND_GUIDE.md`.
> Rule: facts only — every claim below names file paths, commands run, and observed output. No guessing.
> Definition of fully-working used here: single-node trusted-LAN deployment where (1) build/vet/short-suite green, (2) enroll→events→dispatch works, (3) updates verify end-to-end, (4) TLS is on by documented default path, (5) backup→restore drilled, (6) tenant isolation proven by test, (7) docs match code. Multi-org/internet at scale stays out of scope until CI/Linux gates run (no 64-bit cgo on this Windows box — recorded, not guessed).

## Blockers inventory (evidence, no guessing)

| # | Blocker | Evidence (file / observed) | Closes by |
| - | ------- | -------------------------- | --------- |
| B1 | First tagged push never done; daemonset digest `0000` | `deploy/daemonset.yaml:98` image `...v0.1.1@sha256:0000...` with REPLACE-ME comment; `git log` has no `v*` tag path verified | Code: script + docs (cannot push tags from here without your remote auth) |
| B2 | Signing ceremony not executed (code ready, keys absent) | `internal/server/update_sign.go:25-28` returns `""` when `TRACE_UPDATE_SIGNING_KEY` unset; `internal/edr_agent/updater/updater.go:500-504` refuses everything when unkeyed; no `TRACE_UPDATE_*` in env here | Code: `trace update-keys gen/publish` tooling + docs; ops step (your keys) stays yours |
| B3 | `-race`/kill-9/soak/stress/malware/e2e/DuckDB gates deferred | `go version go1.26.4 windows/amd64`; race attempt fails `cc1.exe: sorry, unimplemented: 64-bit mode not compiled in`; `yma/FIX_PLAN.md:286-287` records deferral | Code: CI workflow that runs them on Linux; local: run what's runnable, record the rest as deferred-with-proof |
| B4 | Backup→restore never drilled on this tree | `internal/storage/snapshot/*_test.go` unit round-trip exists; `deploy/*-test.sh` scripts still reference `--api-key` enroll (pre-provision-token); no drill log exists | Code: update drill scripts to provision-token flow; run snapshot round-trip + rotation test; record output |
| B5 | Tenant-A/B isolation proven only by unit predicates, no live two-org drill | `internal/server/pb.go` + `internal/db/db.go` carry `org_id` + backfill; `handleEDRRegister` ignores client `OrgID` (`internal/server/edr.go:159`); no live two-org test exists | Code: add server test with two orgs asserting cross-org 403/empty; docs step for your manual drill |
| B6 | TLS on by flag, not by default path | `cmd/trace/serve.go:369-371` + `server_cmd.go:63-65` accept `--tls-cert/--tls-key`; `internal/server/admin.go:693-694` warns plaintext; `cmd/trace/genkey.go` writes cert 0644 + key 0600+Chmod; no `--tls-auto` wiring in serve path | Code: wire `--tls-auto` (genkey-equivalent self-signed into `~/.trace/tls`, 0700/0600) + plaintext-refuse flag; docs updated |
| B7 | Docs drift (auth + enroll) | `docs/testing-guide.md:863,950,1066,1199` + `deploy/{crash,soak}-test.sh:15,21,28,51,82,100` still use `--api-key` enroll; `docs/user-guide.md:927`, `cli-reference.md:404-419` already document provision-token (proof the new flow is the documented one) | Code: update stale scripts/docs to provision-token flow |
| B8 | `go mod tidy` promotion already landed? | `go.mod:14` shows `golang.org/x/mod v0.37.0` direct (F3 done); verify `go mod tidy -check`-clean or record diff | Verify only |

## Exit criteria (fully-working = all true)

1. `CGO_ENABLED=0 go build ./...` exit 0.
2. `CGO_ENABLED=0 go vet ./...` exit 0 except pre-existing `etw_windows.go:250 unsafe.Pointer` (Windows API, recorded in prior logs).
3. `CGO_ENABLED=0 go test ./... -short -count=1 -p 2` zero `FAIL` lines (full output saved to `yma/GATES.log`).
4. Closure greps zero: `synchronous=OFF`, `OR org_id` (code, not comments), `InsecureSkipVerify` (code), `:latest` + `CHANGE_ME` + `tracetrace` in deploy (docs history excluded), `sh -c` with variable input in response paths.
5. New regression tests green: tenant-A/B isolation, TLS-auto smoke, backup rotation filter, provision-token enroll round-trip (httptest).
6. Live drills recorded: backup snapshot→restore round-trip on a temp dir; server boot writes 0600 seed key; provision-token mint→enroll→`edr list` smoke (commands + observed output in `yma/GATES.log`).
7. Docs match code: testing-guide + crash/soak scripts use provision-token flow; deployment guide has TLS-auto + ceremony + digest steps.
8. Residuals explicitly recorded (not silently dropped): ghcr digest needs your `crane digest` after tag push; signing keys are yours to generate; `-race`/soak/CGO gates need Linux CI.

## Work plan (code changes, minimal and boring)

### W0 Tenant-A/B proof (code, tests only)
- Add `internal/server/tenant_isolation_test.go`: two orgs, user+agent in each; assert cross-org reads return 403/empty for nodes/investigations/agents/events/actions; assert legacy `''` rows invisible to tenants.
- Files: new test file only. No schema/route changes (predicates already landed).

### W1 TLS-auto + plaintext-refuse flag (code)
- `cmd/trace/serve.go` + `cmd/trace/server_cmd.go`: implement `--tls-auto` (call the same generator as `cmd/trace/genkey.go` into `~/.trace/tls/`, dir 0700, cert 0644, key 0600+Chmod); add `--tls-require` (refuse to serve plaintext when set; default warn, matching `admin.go:693`).
- `cmd/trace/testdata/golden/serve.txt` + `server.txt`: regenerate (`UPDATE_GOLDEN=1`).
- Docs: deployment-guide TLS-auto section.

### W2 Signing-key tooling (code, ceremony stays yours)
- `cmd/trace/update-keys.go` (new): `gen` (offline ed25519, prints pubkey hex + seed handling instructions, never logs private to stdout twice), `publish` (writes `.sha256`+`.sig` sidecars for a release dir), `verify` (local check of a published dir).
- Wire nothing into the updater trust root (already fail-closed); tool only mints/checks artifacts.
- Docs: deployment-guide ceremony steps reference the tool.

### W3 Backup/restore + enroll drills (scripts + tests)
- `deploy/crash-test.sh`, `deploy/soak-test.sh`: replace `--api-key` enroll with provision-token flow (`admin token mint` → `--provision-token`); keep everything else.
- `docs/testing-guide.md`: same replacement for the 4 stale spots; append gate-status section update (what ran here vs deferred).
- Add `internal/storage/backup/rotation_filter_test.go` if missing (foreign files never deleted); snapshot round-trip already covered (`snapshot_test.go:12`).
- Run: snapshot create→restore on temp dir; rotation test; enroll smoke (httptest-level where live server is impractical here).

### W4 Digest/docs hygiene (code + docs)
- `deploy/daemonset.yaml`: keep `0000` (cannot invent a digest — facts only) but add a `scripts/pin-digest.sh` (crane digest → replace + verify) + docs step. No fake digest committed.
- `docs/deployment-guide.md` + `docs/user-guide.md`: TLS-auto, ceremony tool, digest pinning, provision-token enroll as the only documented path.
- `yma/STATUS_AND_GUIDE.md`: refresh §4 (honest list shrinks to ops-only steps).

## Verification (Wave B, recorded to yma/GATES.log)
- `CGO_ENABLED=0 go build ./...` → exit code + head.
- `CGO_ENABLED=0 go vet ./...` → filtered output (ETW note only).
- `CGO_ENABLED=0 go test ./... -short -count=1 -p 2` → zero-FAIL grep + tail.
- Closure greps (B7 set) → zero hits with command lines shown.
- New tests: tenant isolation, TLS-auto smoke, rotation filter, enroll round-trip → PASS lines.
- Live drills: seed-key 0600 check, token mint→enroll→list transcript (redacted secrets).
- `-race`/kill-9/soak/CGO: attempt, record verbatim blocker (MinGW), mark deferred — no fake green.

## What I need from you (explicit asks, nothing else)
1. Push permission / tag creation for `v0.1.1` (or tell me the tag) — digest pinning needs a real `crane digest` output I cannot invent.
2. Whether to keep the `0000` digest placeholder failing-closed (current: comment says must-not-apply) or switch daemonset to tag-only until the digest exists.
3. Your TLS posture: self-signed via `--tls-auto` acceptable for LAN, or bring your own CA/cert paths?
4. Signing keys: you generate offline (I provide the tool + verify steps), or want me to generate a DEV-only pair marked as such?
