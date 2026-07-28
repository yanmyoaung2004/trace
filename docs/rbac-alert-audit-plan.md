# RBAC, Alert Fatigue & Audit Trail — Implementation Plan

## Current State

| Feature | Current | What's missing |
|---------|---------|----------------|
| **RBAC** | Roles exist in DB (`admin`, `analyst`), auth middleware checks role, but only `adminOnly` wrapper is enforced. No granular permissions. All API keys are full-access. | Granular permissions, read-only access, endpoint-level checks, permission management UI |
| **Alert fatigue** | 5-minute dedup window per (title, ruleID). No suppression rules, no escalation thresholds. | Suppression rules, threshold escalation, time-based decay, per-rule rate limits |
| **Audit trail** | No audit logging at all. | Append-only event log for all mutations, signed entries, query API |

---

## Phase 1: RBAC (5-7 days)

### 1.1 Permission model
- Define roles: `admin` (full access), `analyst` (read/write own org), `viewer` (read-only)
- Define permissions per endpoint category (cases, investigations, agents, compliance, users)
- Store role→permissions mapping in config or DB

### 1.2 Permission middleware
- Replace `protected` wrapper with permission-checking middleware
- Each endpoint registers required permission (e.g., `permCaseWrite`, `permAgentRead`)
- Middleware checks role→permission mapping before allowing access

### 1.3 API key scoping
- Add `scope` field to API keys (current: full-access, new: `read-only`, `cases-only`)
- User creation and key rotation allow setting scope

### 1.4 Multi-tenant isolation
- Org admins can only see their own org's data
- Super-admin sees all orgs
- Already partially implemented (`org_id` column exists on most tables)

### 1.5 CLI management commands
- `trace admin user create --role viewer --scope read-only`
- `trace admin user list` shows role and scope
- `trace admin user rotate-key <email> --scope cases-only`

---

## Phase 2: Alert Fatigue (5-7 days)

### 2.1 Suppression rules
- `trace alert rule suppress --rule-id R123 --duration 1h` — suppress alerts from a rule
- `trace alert rule suppress --source 10.0.0.5 --duration 24h` — suppress by source
- Store in DB with expiry time, checked before creating alerts

### 2.2 Threshold escalation
- `trace alert rule threshold --rule-id R123 --count 5 --window 10m` — only alert after 5 matches in 10 minutes
- Alerts are queued until threshold is reached, then escalated severity
- Window slides, count resets after window expires

### 2.3 Time-based decay
- Repeated alerts from same source get increasing suppression intervals
- 1st alert → immediate, 2nd → wait 1m, 3rd → wait 5m, 4th → wait 30m
- Configurable per rule (or default algorithm)

### 2.4 Alert aggregation
- Group identical alerts from the same source within a time window
- Instead of 10 alerts, show 1 alert with count=10
- Aggregated alerts have `repeat_count` field

### 2.5 CLI management
- `trace alert rule list` — show rules with suppression/threshold config
- `trace alert rule update --rule-id R123 --max-rate 5/h`
- `trace alert rule reset --rule-id R123` — clear suppression state

---

## Phase 3: Audit Trail (3-5 days)

### 3.1 Append-only audit log
- New table `audit_log` with columns: `id`, `timestamp`, `actor_id`, `actor_email`, `action`, `resource_type`, `resource_id`, `details JSON`, `signature`
- All mutating endpoints log before/after state
- Signature = HMAC-SHA256 of `(timestamp + actor + action + resource + details)`

### 3.2 Mutation hooks
- Cases: create, update, delete, add evidence, add IOC, close
- Investigations: create, update status, approve, deny
- Agents: register, revoke, dispatch action
- Users: create, update role, rotate key
- Compliance: assess, set evidence, generate report

### 3.3 Tamper detection
- Integrity check: `trace audit verify` recomputes signatures and reports any mismatch
- Chain: each entry's signature includes hash of previous entry (blockchain-light)
- If an entry is modified, its signature AND all subsequent signatures become invalid

### 3.4 Query API
- `GET /api/v1/audit?resource=cases&actor=user@example.com&since=2026-01-01`
- `trace audit query --resource cases --since 7d` CLI command
- Paginated, filterable by actor, resource, action, time range

---

## Effort Summary

| Phase | Duration | Dependencies | Risk |
|-------|----------|-------------|------|
| **1. RBAC** | 5-7 days | Existing auth middleware | Low (mostly additive) |
| **2. Alert Fatigue** | 5-7 days | SIEM engine | Medium (state management) |
| **3. Audit Trail** | 3-5 days | None | Low (append-only) |

**Total**: ~3 weeks for a production-grade security operations platform.
