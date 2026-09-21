# Trace — Fully-Working Handoff Report

> Date: 2026-09-21. Code root: `dev/` (run every command from `dev/`).
> Repo: `github.com/yanmyoaung2004/trace` (`origin` = `https://github.com/yanmyoaung2004/trace.git`).
> Scope: trusted single-node LAN. NOT internet-facing, NOT multi-tenant prod.
> Related files: `yma/FULLY_WORKING_PLAN.md` (plan), `yma/GATES.log` (gate evidence),
> `yma/STATUS_AND_GUIDE.md` (usage guide), `yma/AUDIT.md`, `yma/FIX_PLAN.md`.

---

## 1. Where things stand (done vs not done)

### DONE — code-side, committed, proven

| # | Item | What changed (files) | Proof |
| - | ---- | -------------------- | ----- |
| 1 | Build/vet/short-suite green | — (no code change) | `CGO_ENABLED=0 go build ./...` exit 0; `go vet ./...` clean except pre-existing `etw_windows.go:250 unsafe.Pointer`; `go test ./... -short -count=1 -p 2` zero `FAIL` lines. Recorded in `yma/GATES.log` (59 lines). |
| 2 | Tenant-A/B isolation proven by test | `internal/server/tenant_isolation_test.go` (new, 361 lines); nil-metrics guard in `internal/server/sync.go` | `go test ./internal/server/ -run TestTenantIsolationTwoOrgs` → ok. Asserts: two orgs, cross-org reads 403/empty (nodes, investigations, agents, events, actions), legacy `''` rows invisible, client `OrgID` ignored. |
| 3 | TLS on by documented flag path | `cmd/trace/tls_auto.go` (new: `ensureSelfSignedTLS` + `resolveServerTLS`); wired in `cmd/trace/server_cmd.go` + `cmd/trace/serve.go`; regened `cmd/trace/testdata/golden/{root,serve,server}.txt` | `trace server --tls-auto` generates genkey-equivalent RSA-2048/1yr pair into `~/.trace/tls/` (dir 0700, cert 0644, key 0600+Chmod, reuse path); `--tls-require` refuses plaintext (default: warn); daemon `--export` plaintext refused when set. |
| 4 | Update-signing tooling | `cmd/trace/update-keys.go` (`gen`/`publish`/`verify`); one-line wiring in `cmd/trace/root.go` | Byte layout mirrors `internal/server/update_sign.go` + `internal/edr_agent/updater/updater.go`: `.sha256` = hex digest, `.sig` = base64 ed25519 over RAW digest. Agents stay fail-closed when unkeyed. NO production keys generated (facts only). |
| 5 | Enroll + drill scripts on provision-token flow | `deploy/crash-test.sh`, `deploy/soak-test.sh`, `docs/testing-guide.md` (4 stale spots), `cmd/trace-agent/agent_integration_test.go` (heartbeat assertion fixed to ticker reality) | `TestAgentRegistrationAndHeartbeat` PASS (~29s); `storage/backup` + `storage/snapshot` ok; testing-guide gate-status section updated. |
| 6 | Digest pinning (script, not the digest) | `scripts/pin-digest.sh`; `deploy/daemonset.yaml` comment hardened (still `0000`, must-not-apply); `docs/deployment-guide.md` + `docs/user-guide.md` sections | Script validates `sha256:`+64hex, rewrites tag+digest, fails on `0000`. No fake digest committed. |

Commits (this pass): `6e3927b feat(fully-working): ...` (20 files) then
`6e7f626 docs(yma): fully-working plan Wave B completion + gate evidence`.
Tree was clean at handoff (`git status --short` empty).

### NOT DONE — ops-only, needs you (nothing else code-side blocks)

| # | Item | Why it's yours | Exact step (below) |
| - | ---- | -------------- | ------------------ |
| A | Release tag for the CURRENT code + ghcr digest pin | `v0.1.1` tag exists but points at an old commit (127 commits behind HEAD); digest must come from the real registry (`crane` not installed here; I refuse to invent digests) | Step 1 |
| B | Update-signing keys (generate offline, publish, enforce) | Private keys must never be minted by an agent session | Step 2 |
| C | Linux CI gates (`-race`, kill-9/soak, DuckDB CGO) | This box: `go1.26.4 windows/amd64`, race fails `cc1.exe: sorry, unimplemented: 64-bit mode not compiled in` (recorded in `yma/GATES.log`) | Step 3 |
| D | Single-node smoke on YOUR machine (server → token → enroll → events → backup) | Only you can run your LAN binaries | Step 4 |
| E | TLS posture choice | Self-signed LAN vs your CA | Step 5 |

---

## 2. What YOU do — detailed steps

Work from `D:/Projects_And_Learning/AI/Trace/dev` unless noted.
PowerShell shown for local commands; tagged-push/digest steps assume a shell with
`git`, `go`, `docker`, and `crane` (`go install github.com/google/go-containerregistry/cmd/crane@latest`).

### Step 0 — Sanity: rebuild + confirm gates (5 min, Windows PowerShell)

```powershell
cd D:/Projects_And_Learning/AI/Trace/dev
$env:CGO_ENABLED = "0"
go build ./...
go vet ./...
go test ./... -short -count=1 -p 2 2>&1 | Select-String "^FAIL" | Select-Object -First 10
# expect: build exit 0, vet only the known etw_windows.go:250 note, zero FAIL lines
```

Reference: full gate transcript lives in `yma/GATES.log`.

### Step 1 — Tag the CURRENT code and pin the agent digest (15–30 min)

**Why:** tag `v0.1.1` (msg `v0.1.1 — Trace Storage Engine, ...`) exists locally AND on
origin (`git ls-remote --tags origin` shows it) but points at `244b42e`, which is
127 commits behind HEAD (`git rev-list --count v0.1.1..HEAD` = 127).
The daemonset image `ghcr.io/yanmyoaung2004/trace-agent:v0.1.1@sha256:0000...`
(`deploy/daemonset.yaml:100`) is a failing-closed placeholder — MUST NOT be applied as-is.
CI only pushes images on tag pushes (`.github/workflows/ci.yml:117-131`);
the release workflow builds artifacts on `v*` tags (`.github/workflows/release.yml:3-6`)
but does NOT build/push the agent image — know that before promising a digest.

**Do:**

```bash
cd dev
git status --short            # expect clean
git log --oneline -3          # expect 6e7f626 on top

# 1a. Create the next tag on CURRENT head (do NOT move v0.1.1 — it is already on origin).
#     Suggested: v0.1.2 (patch: tenant test, TLS-auto, update-keys tool, drill fixes).
git tag -a v0.1.2 -m "v0.1.2 — tenant isolation proof, TLS-auto, update-keys tooling, provision-token drills"
git push origin v0.1.2

# 1b. Watch CI + release on GitHub (release.yml runs tests + cross-builds on v*).
#     https://github.com/yanmyoaung2004/trace/actions

# 1c. Build + push the AGENT image for that tag (release.yml does not do this;
#     Dockerfiles are digest-pinned already: Dockerfile, deploy/Dockerfile.agent).
docker build -f deploy/Dockerfile.agent -t ghcr.io/yanmyoaung2004/trace-agent:v0.1.2 .
docker push ghcr.io/yanmyoaung2004/trace-agent:v0.1.2

# 1d. Take the REAL digest from the registry — never hand-type one:
crane digest ghcr.io/yanmyoaung2004/trace-agent:v0.1.2
# expect: sha256:<64 lowercase hex>

# 1e. Pin tag+digest together (validates shape, rewrites the image line, fails on 0000):
TAG=v0.1.2 DIGEST=$(crane digest ghcr.io/yanmyoaung2004/trace-agent:v0.1.2) scripts/pin-digest.sh "${TAG}" "${DIGEST}"
# or: scripts/pin-digest.sh v0.1.2 <paste-digest>

# 1f. Verify + commit:
grep 'image:' deploy/daemonset.yaml
crane digest ghcr.io/yanmyoaung2004/trace-agent:v0.1.2   # must print the same DIGEST
git add deploy/daemonset.yaml
git commit -m "chore(deploy): pin trace-agent image to v0.1.2 digest"
git push origin main
```

**If the agent image is published by some other pipeline** (not the manual docker
build above), substitute its tag in 1c–1e — the rule is unchanged: digest comes from
`crane digest` of the pushed tag, never invented.

**If you prefer tag-only until the registry exists:** say so and I will switch the
manifest to a plain `:vX.Y.Z` tag with a must-pin-before-prod comment. Current state
(failing-closed `0000`) is the safe default.

### Step 2 — Update-signing ceremony: keys → publish → enforce (20 min + one release cycle)

**Why:** server returns `""` signature when `TRACE_UPDATE_SIGNING_KEY` is unset
(`internal/server/update_sign.go:25-28`); agents refuse everything when unkeyed
(`internal/edr_agent/updater/updater.go:500-504`). Code is fail-closed; keys are yours.
Ceremony doc: `docs/deployment-guide.md` §"Update signing ceremony".

**Do (on an OFFLINE machine for gen):**

```bash
cd dev
go build -o /tmp/trace ./cmd/trace

# 2a. Generate once, offline. Seed file is 0600, private seed NEVER printed with --out:
/tmp/trace update-keys gen --out /safe/offline/update-seed.b64
# prints: Public key hex (TRACE_UPDATE_VERIFY_KEY_HEX) + server env instruction.
# Without --out the seed prints EXACTLY ONCE — save it immediately, never commit/log it.

# 2b. Server side only: set the signing seed (from the offline file):
export TRACE_UPDATE_SIGNING_KEY="$(cat /safe/offline/update-seed.b64)"

# 2c. Fleet side: publish the hex public key to every agent (config or env — NEVER from the network):
export TRACE_UPDATE_VERIFY_KEY_HEX="<hex-from-gen>"

# 2d. Publish sidecars for the release dir (.sha256 = hex digest,
#     .sig = base64 ed25519 over the RAW 32-byte digest):
/tmp/trace update-keys publish --dir ./release/
# refuses on empty dir; prints "published <name>  sha256:<hex>" per artifact

# 2e. Check locally, fail-closed on missing/mismatch:
/tmp/trace update-keys verify --dir ./release/ --verify-key "$TRACE_UPDATE_VERIFY_KEY_HEX"
# expect: "verified <name>  sha256+sig ok" per artifact

# 2f. Dual-publish .sha256 + .sig alongside artifacts for ONE release unsigned-tolerant
#     (unkeyed fleets warn, never refuse), then enforce: keyed agents refuse unsigned,
#     tampered, or downgraded (non-semver-newer over HTTPS, same-origin) updates.
```

Byte layout (do not change one side without the other):
`cmd/trace/update-keys.go:5-20`, `internal/server/update_sign.go`,
`internal/edr_agent/updater/updater.go verifySignatureHex`, `cmd/trace/update.go verifyArtifactSignature`.

### Step 3 — Read Linux CI (5 min after push)

**Why:** `-race`, kill-9/soak, DuckDB CGO cannot run on this Windows box
(MinGW `cc1.exe` 64-bit block, recorded in `yma/GATES.log:24-28`).
CI already runs them: `.github/workflows/ci.yml:64-68`
(TSE race, TSE DuckDB CGO, TSE load, TSE crash recovery) + fuzz jobs (`:84-97`) +
Windows vet (`:149-150`).

**Do:**

1. Push `main` (and the tag from Step 1).
2. Open `https://github.com/yanmyoaung2004/trace/actions` → latest run.
3. Required green: `Vet (linux)`, `TSE race detection`, `TSE DuckDB (CGO)`,
   `TSE load tests`, `TSE crash recovery`, `Vet (windows)`.
4. If `TSE DuckDB (CGO)` fails on missing `gcc`, CI installs it (`ci.yml:40-41`) —
   paste me the failing step log and I fix the workflow/code (not your machine).

### Step 4 — Single-node smoke on YOUR machine (30 min, trusted LAN)

**Why:** proves enroll→events→dispatch→backup on your binaries. Docs:
`yma/STATUS_AND_GUIDE.md` §3, `docs/deployment-guide.md` §"Agent enrollment".

```powershell
cd D:/Projects_And_Learning/AI/Trace/dev
go build -o trace.exe ./cmd/trace
go build -o trace-agent.exe ./cmd/trace-agent
.\trace.exe version
.\trace.exe config check

# 4a. Start the server (first boot writes ONCE, 0600, never prints: ~/.trace/data/admin_api_key)
.\trace.exe server --http-addr :8080
# new window:
$env:TRACE_API_KEY = (Get-Content ~/.trace/data/admin_api_key)
curl.exe -H "Authorization: Bearer $env:TRACE_API_KEY" http://localhost:8080/healthz   # expect: ok

# 4b. Org + user + provision token (admin client: --server flag or TRACE_SERVER_URL,
#     --api-key flag or TRACE_API_KEY; see cmd/trace/admin.go:339-360)
.\trace.exe admin org create "test-org"              # note the org ID
.\trace.exe admin token mint <org-id> --label smoke  # token prints ONCE — copy it now
.\trace.exe admin token list --org <org-id>          # metadata only (prefix, expiry, used)

# 4c. Enroll the agent (token-only; client --api-key on enroll is REJECTED by design)
.\trace-agent.exe --server http://127.0.0.1:8080 --provision-token <tok> --verbose
# expect: "registered with server (id: ...)", heartbeat loop starts

# 4d. Server side: list, view, stream events
.\trace.exe edr list --server http://127.0.0.1:8080 --api-key $env:TRACE_API_KEY
.\trace.exe edr view <agent-id> --server http://127.0.0.1:8080 --api-key $env:TRACE_API_KEY
.\trace.exe edr events <agent-id> --type alert --min-severity 3 --limit 10 --server http://127.0.0.1:8080 --api-key $env:TRACE_API_KEY

# 4e. Contained dispatch drill (approval-gated; audit row written)
.\trace.exe edr dispatch <agent-id> block_ip --ip 203.0.113.42 --server http://127.0.0.1:8080 --api-key $env:TRACE_API_KEY
.\trace.exe approval pending
# approve with the printed token, then verify + check the audit row (see STATUS_AND_GUIDE §3.7–3.8)

# 4f. Backup → restore round-trip (TSE snapshot; standalone, no server needed)
.\trace.exe tse snapshot --storage-path ~/.trace/tse -o backup.tar.gz
.\trace.exe tse recover --from backup.tar.gz --storage-path <empty-test-dir>
# expect: restore completes; do NOT recover into the live dir. Statuses: tse status/flush/inspect/metrics.
```

**Pass = all of:** healthz `ok`; token mints once; agent registers; `edr list` shows it;
events stream; dispatch → approval → audit; snapshot → recover into empty dir clean.
**Paste me the first failing command + its full output** and I fix code (not your env).

### Step 5 — TLS posture: pick ONE (2 min decision, then 5 min)

- **Option 1 — LAN/self-signed (easiest, matches the new code):**
  `trace server --tls-auto` (pair into `~/.trace/tls/`, reuse on reboot),
  `curl -k https://localhost:8080/healthz` → `ok`;
  enforce with `trace server --tls-require --tls-auto` (refuses plaintext;
  default is warn-and-serve, matching `internal/server/admin.go:693`).
  Verify perms: `stat -c '%a %n' ~/.trace/tls ~/.trace/tls/cert.pem ~/.trace/tls/key.pem`
  → `700 / 644 / 600`. Full text: `docs/deployment-guide.md` §"TLS-auto".
- **Option 2 — Your CA/certs:** `trace server --tls-cert /etc/certs/cert.pem --tls-key /etc/certs/key.pem`
  (explicit cert/key wins over `--tls-auto`).
- Either way: never expose `:8080` raw to the internet; the daemon's `--export`
  server is plaintext-only and `--tls-require` refuses it by design.

---

## 3. Follow-ups AFTER the five steps (in order, not now)

1. Nightly backup schedule for `~/.trace` + monthly restore drill (code enforces 95%
   disk refusal; scheduling is ops).
2. Second host enroll → scheduled hunts → weekly compliance report
   (`yma/STATUS_AND_GUIDE.md` §3.9, §5).
3. Tenant-A/B live drill (unit proof exists; run two orgs before sharing one server).
4. Wider rollout. Keep `run_script` denied (flag + signed policy + approval required).

---

## 4. If something fails — what to send me

1. The exact command you ran (full flags).
2. Full output (not a summary) — or the CI step log URL.
3. `git log --oneline -3` + `git status --short` (so I know what tree you ran).
4. For agent issues: agent log lines around `registered with server` + server side `edr view`.

I fix code from that; I will not ask you to re-run what you already pasted.

---

## 5. Quick reference (exact names)

| Thing | Path / name |
| ----- | ----------- |
| Plan + gate evidence | `yma/FULLY_WORKING_PLAN.md`, `yma/GATES.log` |
| Usage guide | `yma/STATUS_AND_GUIDE.md` §3–§5 |
| Tenant proof test | `internal/server/tenant_isolation_test.go` |
| TLS helper | `cmd/trace/tls_auto.go` (`ensureSelfSignedTLS`, `resolveServerTLS`) |
| Signing tool | `cmd/trace/update-keys.go` (`gen`/`publish`/`verify`) |
| Digest script | `scripts/pin-digest.sh` |
| Daemonset (do NOT apply as-is) | `deploy/daemonset.yaml:100` (`0000` placeholder) |
| Admin enroll/token CLI | `cmd/trace/admin.go` (`token mint <org-id>`, `token list --org`) |
| Admin auth | `--server` flag / `TRACE_SERVER_URL`, `--api-key` flag / `TRACE_API_KEY` (`admin.go:339-360`) |
| EDR CLI | `cmd/trace/edr_cmd.go` (`list`, `view <id>`, `events <id>`, `dispatch <id> <action>`, `dismiss`, `revoke`) |
| Agent flags | `cmd/trace-agent/main.go:26-37` (`--server`, `--provision-token`, `--api-key` re-enroll only) |
| TSE snapshot/recover | `cmd/trace/tse_cmd.go:88-127` (`snapshot`), `:215-246` (`recover`) |
| Server TLS flags | `cmd/trace/server_cmd.go:70-74` |
| CI gates | `.github/workflows/ci.yml:40-97` (linux), `:149-150` (windows vet) |
| Release (tags `v*`) | `.github/workflows/release.yml` (no agent image push — Step 1c is manual) |
| Image Dockerfiles (pinned) | `Dockerfile`, `deploy/Dockerfile.agent` |
| Drill scripts | `deploy/crash-test.sh`, `deploy/soak-test.sh`, `deploy/e2e-test.sh` |
| Seed admin key (0600, write-once) | `internal/server/server.go:18-58` (`~/.trace/data/admin_api_key`) |
