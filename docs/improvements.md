# Architecture Improvements

## 1. SIEM — built natively, not imported

Wazuh is a dependency with a server cluster and agents for every endpoint. Instead, ship a lightweight SIEM engine inside the edge node:

- **Ingestion** — file watcher for local logs (`/var/log/`, Windows Event Log API), syslog listener, and a pluggable receiver interface for custom sources
- **Parsing & normalization** — decoder framework that maps raw logs (syslog, JSON, EVTX, CSV) to a unified event schema
- **Rule engine** — real-time correlation rules with windowed matching (e.g., "5 failed logins in 60s from same source IP"). Rules are YAML, user-editable
- **Alerting** — rules produce alerts with severity, MITRE mapping, and structured evidence. Alerts feed directly into the Dispatch Agent for investigation

The SIEM engine is a plugin that can be swapped or disabled. No Wazuh server to maintain, no agents to deploy across the fleet. Log sources declare themselves — the engine adapts.

```
Log Source ──► Decoder ──► Normalized Event ──► Rule Engine ──► Alert ──► Dispatch Agent
```

## 2. SOAR — built as playbooks + agent orchestration

SOAR is not a separate system. It's the natural output of the agent architecture:

- **Playbook library** — YAML playbooks encode common SOC workflows. "Alert arrives → enrich IP from VT → check against threat intel → search local logs for related events → assign severity → suggest remediation → generate incident report"
- **Automated response** — playbooks can include actions: add IP to blocklist, quarantine file via OS API, create firewall rule, restart service. Define *actions* as a new agent type (Response Agent) with capability declarations
- **Human-in-the-loop** — playbook steps can pause and wait for analyst approval before executing destructive actions
- **Incident management** — each investigation is an incident record with status (open/investigating/resolved), timeline, evidence artifacts, and final report. Stored in SQLite, exportable as PDF

Playbook example:

```yaml
name: phishing-investigation
trigger: alert.type == "phishing"
steps:
  - agent: detection
    action: extract_iocs
    params: { email: ${alert.source} }
  - if: ${result.urls}
    agent: detection
    action: vt_batch_lookup
    params: { urls: ${result.urls} }
  - agent: knowledge
    action: mitre_mapping
    params: { technique: initial_access.phishing }
  - agent: knowledge
    action: enrich_context
    params: { iocs: ${outputs.extract_iocs.all} }
  - wait: analyst_approval
    label: "Block domains on firewall?"
  - if: ${approval.granted}
    agent: response
    action: block_domains
    params: { domains: ${outputs.vt_batch_lookup.malicious} }
  - agent: host
    action: generate_report
  - agent: host
    action: update_status
    params: { status: resolved }
```

## 3. Deployment model

Static Go binary that embeds everything (SIEM engine, agents, SQLite, intel DB). Single file deployment. No Docker, no Python runtime.

## 4. Hybrid planner: playbooks + LLM

Ship a library of built-in investigation playbooks for common patterns:
- "Check file hash against cache, YARA, and VT"
- "Investigate process name against known malware families"
- "Parse Windows event ID 4625 and correlate with brute-force patterns"

Match user intent against playbooks first. If no match, fall back to LLM decomposition. Playbooks run fully offline. LLM planner requires connectivity.

## 5. Plugin system before agent code

Every agent implements a fixed interface:

```go
type Agent interface {
    Name() string
    Capabilities() []Capability
    Execute(ctx context.Context, input Input) (Output, error)
}
```

Agents are loadable plugins discovered at startup. Detection v1 ships with YARA + VT. v2 adds an ML model. Need a new SIEM log source? Write a decoder plugin.

## 6. Ship threat intel with the box

SQLite database pre-populated with:
- MITRE ATT&CK techniques with descriptions
- CVE-to-severity mappings
- Known YARA rules
- Known IOC hashes

Update via .trace update-intel` or periodic background fetch.

## 7. Limit VT dependency

VT is enrichment, not primary detection. Cache aggressively by hash with TTL. Batch lookups. Rank confidence with local checks (YARA + PE metadata) first.

## 8. SQLite for everything

Single SQLite database in WAL mode serves as:
- Task queue (agents poll `tasks` table)
- Result store
- Cache with TTL
- Configuration store
- Threat intel data
- Incident/alert management

No Redis, no message broker, no separate DB. One file, trivially backup-able.

## 9. File-based agent communication

Agents exchange file references, not raw payloads in JSON:

```
/data/shared/<investigation_id>/
  host/initial_request.json
  host/final_report.json
  detection/hash_lookup.json
  detection/yara_result.json
  detection/vt_result.json
  knowledge/mitre_mapping.json
```

No agent waits synchronously. Supports async, retry, and partial results.

## 10. Append-only investigation log

Every event appended to JSONL:

```jsonl
{"ts":"...","type":"intent","data":"check this file"}
{"ts":"...","type":"task_dispatched","agent":"detection","action":"hash_lookup"}
{"ts":"...","type":"task_result","agent":"detection","confidence":0.85}
{"ts":"...","type":"report_generated","confidence":0.82}
```

Audit trail, replay, training data, step-by-step explainability.

## 11. Pre-warm cache on install

On first deploy: batch known malware hashes against VT (if licensed), seed MITRE and CVE data, validate all agents initialize.

## 12. Go for edge distribution

Static binary, ~10 MB, no runtime dependencies. Embed SQLite via modernc.org/sqlite (no CGo). Embed rules and intel DB. Single binary download, run, done.
