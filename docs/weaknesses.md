# Trace — Current Weaknesses & Gaps

> Assessment date: 2026-07-28
> System-wide rating: 8.8/10

## Architecture

| Weakness | Impact | Priority |
|----------|--------|----------|
| **Single-process server** | No horizontal scaling. Multi-node is active-passive only (one at a time). If it crashes during a traffic spike, agents buffer locally until it comes back. | High |
| **SQLite hot tier scaling ceiling** | ~500K ev/s on one node. Can't shard across machines. Elasticsearch does millions/sec across a cluster. | Medium |
| **No automated backup** | TSE snapshot exists but no scheduled backup/restore strategy. Data directory loss = total data loss. | High |

## Security & Operations

| Weakness | Impact | Priority |
|----------|--------|----------|
| **No RBAC** | Anyone with the API key is admin. No read-only analysts, no multi-tenant isolation, no audit log. | High |
| **No alert fatigue management** | 10,000 matching events = 10,000 alerts. No suppression, no threshold escalation, no ML noise reduction. | High |
| **No tamper-proof audit trail** | Analyst actions (case changes, evidence deletion) aren't logged immutably. Compliance auditors will flag this. | Medium |

## Analytics

| Weakness | Impact | Priority | Status |
|----------|--------|----------|--------|
| **PE analysis is signature-only** | No ML classifier for novel malware. | Medium | 🟡 Infrastructure ready, training guide in `docs/ml-training-guide.md` |
| **Static YARA rules** | 17 built-in rules, no auto-update. | Low | 🟢 Fixed — `LoadFromDir()` loads `.yar` files from `~/.trace/yara/` |
| **No visualization** | Plain HTML tables. | Low | 🟢 Fixed — Chart.js timeline + severity charts on dashboard |

## User Experience

| Weakness | Impact | Priority |
|----------|--------|----------|
| **No mobile app** | Analysts can't acknowledge alerts from their phone. Requires terminal or web browser. | Low |
| **No playbook editor UI** | Playbooks are hand-edited YAML files. No drag-and-drop workflow builder. | Low |
| **Agent on Windows is noisy** | Polling-based file monitor generates excessive events. Rate limiting drops legitimate events. Linux with fanotify is clean. | Medium |

## Summary

The system is production-ready for a **small SOC team** (< 5 analysts, < 500K events/sec, single cluster). The gaps are in what separates a demo from a mature enterprise deployment: RBAC, backup, alert fatigue management, and scalability beyond a single node.
