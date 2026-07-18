# Edge Deployment Architecture

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Core language | Go | Static binary, embed everything, cross-compile for any edge OS |
| Persistence | SQLite (WAL mode) | One file, no daemon, zero config, trivially backup-able |
| Playbooks | YAML | Human-editable, no parser to write, version-controllable |
| Plugins | gRPC sidecar (third-party), compiled-in (core) | Language-agnostic for external devs |
| Embedding | Go `embed` | Bundle YARA rules, intel DB, playbooks into binary at compile time |
| LLM calls | Plain HTTP | No SDK lock-in, swap providers by changing URL + key |
| CLI | cobra + pflag | De facto Go standard |
| ML inference | ONNX Runtime (Go bindings) | Ship models without Python runtime |
| Central server | Same Go binary, optional mode | Code reuse, separate config flag |

## Deployment Model

Single self-contained binary. No Docker, no Python runtime, no external services. Download and run.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Edge Node (single binary)       │
│                                               │
│  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │  Host     │  │Knowledge │  │ Detection  │  │
│  │  Agent    │  │  Agent   │  │   Agent    │  │
│  ├──────────┤  ├──────────┤  ├────────────┤  │
│  │ Planner  │  │ RAG      │  │ YARA       │  │
│  │ Orch.    │  │ MITRE DB │  │ PE scan    │  │
│  │ Playbook │  │ CVE cache│  │ VT client  │  │
│  └──────────┘  └──────────┘  └────────────┘  │
│         │           │               │         │
│         └───────────┴───────────────┘         │
│                         │                     │
│                    ┌────┴────┐                │
│                    │ SQLite  │                │
│                    │ (WAL)   │                │
│                    ├─────────┤                │
│                    │ tasks   │                │
│                    │ results │                │
│                    │ config  │                │
│                    │ cache   │                │
│                    │ intel   │                │
│                    └─────────┘                │
│                                               │
│  ┌──────────────┐  ┌──────────────────────┐   │
│  │ File Watcher │  │ Append-Only Inv. Log │   │
│  │ (local logs) │  │   (JSONL / replay)   │   │
│  └──────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Core Design Decisions

### 1. Static binary, zero dependencies

Go binary (~10 MB) embedding SQLite, YARA rules, and a pre-built threat intel DB. Install with one `curl | sh` or a single binary download. No interpreters, no containers, no runtime dependencies on the host OS beyond basic syscalls.

### 2. Hybrid planner: playbooks + LLM

A library of built-in playbooks (YAML) for common investigation patterns:
- "Check file hash against cache, YARA, and VT"
- "Investigate process by name against known malware families"
- "Parse Windows event ID 4625 and correlate with known brute-force patterns"

The orchestrator matches user intent against playbooks first. If no match, falls back to LLM-based decomposition. Playbooks run fully offline. LLM planner requires connectivity.

Playbook format:

```yaml
name: hash-lookup
description: Check a file hash against local cache, YARA, and VirusTotal
steps:
  - agent: detection
    action: hash_lookup
    params:
      hash: ${input.hash}
    on_result: cache_result
  - agent: detection
    action: yara_scan
    params:
      path: ${input.path}
    on_result: merge_confidence
  - agent: detection
    action: vt_lookup
    params:
      hash: ${input.hash}
    timeout: 30s
    optional: true
  - agent: host
    action: synthesize_report
```

### 3. Plugins, not hardcoded agents

Every agent implements a fixed interface:

```go
type Agent interface {
    Name() string
    Capabilities() []Capability
    Execute(ctx context.Context, input Input) (Output, error)
}
```

New detection capabilities ship as separate plugins (shared libraries or compiled-in). The Dispatch Agent discovers available agents at startup via capabilities manifest. Swap or add agents without changing the orchestrator.

### 4. SQLite as everything

A single SQLite database in WAL mode serves as:
- **Task queue** — agents poll a `tasks` table for new work
- **Result store** — agent outputs written to a `results` table
- **Cache** — VT lookups, hash reputations, intel queries with TTL
- **Configuration** — key-value settings, agent enable/disable
- **Threat intel** — pre-bundled MITRE ATT&CK, CVE-to-severity, known IOCs

No Redis, no message broker, no separate DB process. One file. Trivially backup-able.

Task queue pattern:

```sql
CREATE TABLE tasks (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL,
  agent TEXT NOT NULL,
  action TEXT NOT NULL,
  payload TEXT NOT NULL,       -- JSON
  status TEXT DEFAULT 'pending',  -- pending, running, done, failed
  result TEXT,                 -- JSON
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT
);
```

Agents poll with `SELECT ... WHERE status = 'pending' ORDER BY created_at LIMIT 1` and write results back. For event-driven wakeup, use a SQLite trigger + a simple notify mechanism.

### 5. File-based agent communication

Agents exchange references to shared files, not raw payloads in JSON:

```
/data/shared/<investigation_id>/
  host/
    initial_request.json
    final_report.json
  detection/
    hash_lookup_result.json
    yara_result.json
    vt_result.json
  knowledge/
    mitre_mapping.json
    cve_details.json
```

The Dispatch Agent writes the request. Sift Agent reads it, writes results. Dispatch Agent reads results when ready. No agent waits synchronously on another. This naturally supports async, retry, and partial results.

### 6. Append-only investigation log

Every event in an investigation is appended to a JSONL log:

```jsonl
{"ts":"...","type":"intent","data":"check this file"}
{"ts":"...","type":"task_dispatched","agent":"detection","action":"hash_lookup","task_id":"..."}
{"ts":"...","type":"task_result","agent":"detection","action":"hash_lookup","confidence":0.85,...}
{"ts":"...","type":"report_generated","confidence":0.82,...}
```

This gives full audit trail, replay capability for training, and step-by-step explainability for analysts reviewing decisions.

### 7. Offline-first with async enrichment

- **Immediate** — respond from local cache, YARA, PE analysis
- **Async** — queue VT lookups, intel updates, report generation
- **In-place update** — when async results arrive, the investigation report updates automatically; notify the analyst if they're still viewing

The system never blocks on external services. If VT is unreachable, the analyst gets a best-effort answer with "VT lookup pending — results will appear when available."

### 8. Pre-warmed cache on first run

On initial deployment:
1. Populate MITRE ATT&CK techniques with descriptions
2. Seed CVE database for the detected OS version
3. Run a batch lookup of known malware hashes against VT (if licensed) to warm the hash cache
4. Validate all agents initialize correctly

This ensures the first real investigation never hits cold cache and serves as a health check.

### 9. Single binary update strategy

- .trace update` — downloads new binary, verifies signature, swaps atomically
- .trace update-intel` — refreshes threat intel DB from a CDN-hosted snapshot
- .trace plugin install <name>` — downloads a new detection plugin

All updates are signed. Rollback via .trace update --version <prev>`.

## What This Enables

- **Deploy anywhere** — laptop, Raspberry Pi, small VM, cloud instance
- **No UI to install** — CLI-first, optional web dashboard
- **Air-gap capable** — core investigation works with no network
- **One-file state** — backup or move the entire system by copying one SQLite DB
- **Trivial testing** — start binary, run investigation via CLI or API, inspect SQLite for results
- **Pluggable detection** — third-party or custom models added without touching orchestrator

## SIEM — two modes

**Mode 1: Native SIEM engine** (self-contained)
File watcher for local logs, syslog listener, decoder framework for normalization, real-time YAML rule engine with windowed correlation, alert generation feeding into the Dispatch Agent. All in-process, no separate server.

**Mode 2: SIEM connector plugin** (external)
Ingest alerts from existing SIEM systems (Splunk, Elastic, Wazuh, Sentinel) via plugins. The edge node becomes an enrichment and analysis layer on top of whatever SIEM the user already runs. Incoming alerts trigger the same playbook engine. The SIEM plugin interface is: auth, query, receive alert, write back result.

Both modes produce the same internal alert format. Playbooks, agents, and reports work identically regardless of where the alert came from.

## Central server mode

Edge nodes can optionally report to a central Trace server. The server aggregates investigations, provides cross-node correlation, long-term retention, and a team dashboard. Edge nodes continue working fully offline — results sync when connectivity returns. Neither mode depends on the other.

Central server is a separate binary. It's not required for edge nodes to function.

## SOAR

Investigation playbooks define automated triage workflows (enrich → correlate → escalate → remediate). Playbooks include HITL approval steps and response actions (block IP, quarantine file, update firewall). Each investigation is a structured incident record with timeline, evidence, and report.

## Plugin extension interfaces

Every extension point follows the same pattern — a small interface that lets users bring their own backend without modifying the core. Most can ship as shared libraries or standalone sidecars communicating over the same file-based protocol agents use.

**Threat intel feed plugins**
Beyond the bundled SQLite DB. Interface: `Authenticate() → Fetch(ctx, since) → Normalize() → Cache()`. One interface, any source:
- MISP, AlienVault OTX, AbuseIPDB
- STIX/TAXII feeds (CISA, commercial)
- Custom intel pipelines

**Response action plugins**
Beyond local OS actions. Interface: `Name() → Capabilities() → Execute(action, params)`.
- Cloud firewalls: AWS WAF, Cloudflare, pfSense, OPNsense
- EDR: CrowdStrike, Defender, SentinelOne, Velociraptor
- Ticketing: Jira, ServiceNow, TheHive
- Notification: Slack, Teams, PagerDuty, email

**LLM provider plugins**
Swap the planner/decomposition backend without touching agents. Interface: `Decompose(intent, context) → Plan` or `Analyze(context, question) → Answer`.
- OpenAI, Anthropic, Google Gemini
- Local: Ollama, vLLM, llama.cpp
- Enterprise: Azure OpenAI, AWS Bedrock, GCP Vertex

**Reporting/export plugins**
Interface: `Format(investigation) → []byte`.
- HTML dashboard
- PDF incident report
- STIX output for sharing with other SOCs
- CSV for compliance audits
- Email digest

**Log source plugins**
Beyond local file watcher and syslog. Interface: `Name() → Stream(ctx) → Event`.
- S3 bucket (CloudTrail, ALB, VPC Flow)
- Kubernetes events (via k8s API)
- Docker daemon events
- Zeek/Suricata JSON
- Windows Event Collector (forwarded events)

**Storage backend plugins**
SQLite is the default for edge. Interface for alternatives: `Write(investigation) → Read(id) → Query(filter)`.
- Central server: PostgreSQL
- Long-term: Elasticsearch, S3-compatible
- Compliance: immutable append-only store (AWS Glacier, Azure Blob Archive)

**SIEM connector plugins**
Interface: `Connect(config) → Receive() → Alert`. Write results back as investigation findings.
- Splunk, Elastic, Wazuh, Azure Sentinel, Google Chronicle
- Any SIEM with an API

The product is the playbook engine + agents + plugin framework. Everything else — SIEM, threat intel, LLM, storage, notifications, log sources, response actions — is a plugin implementing a known interface.
