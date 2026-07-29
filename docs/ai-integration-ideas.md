# AI/LLM Integration Ideas for Trace

## Current State

Trace already has an LLM dispatch agent with:
- Intent classification (`classify_intent`)
- Investigation planning (`plan_investigation`)
- Report synthesis (`synthesize_report`)
- LRU + SQLite persistent cache (24h TTL)
- Provider chaining (primary → fallback)
- 10s timeout isolation, 2x retry, cost tracking

## Ideas

### 1. AI Alert Triage & Prioritization

**What**: When SIEM fires an alert, LLM reads the alert + context, classifies it as `critical/high/medium/low/informational/false_positive`, and suggests a response.

**Why**: Reduces alert fatigue. Analysts only see alerts the LLM marks as actionable.

**How**:
```
SIEM Alert → LLM Triage →
  - Severity override
  - Suggested playbook
  - Confidence score
  - Natural language explanation
→ If confidence > 90% → auto-create case + run playbook
→ If confidence < 50% → suppress until reviewed
```

**Effort**: 2-3 days

---

### 2. Investigation Co-Pilot

**What**: Chat interface for investigations. Type "what happened with 10.0.0.5 in the last hour?" and get a natural language answer with supporting evidence.

**Why**: Analysts don't need to learn SQL or navigate dashboards for common questions.

**How**:
```
Analyst: "show me all process created by powershell in the last hour"
LLM: → translates to TSE query → executes → formats response
→ "Found 12 processes created by PowerShell between 14:00-15:00:
   1. powershell.exe -enc <base64> [PID: 4521] 14:02
   2. powershell.exe -File scan.ps1 [PID: 4892] 14:15
   ..."
```

**Effort**: 3-4 days

---

### 3. Automated Root Cause Analysis

**What**: Given an alert, trace backward through the event chain to identify the root cause. Answers "how did this happen?" not just "what happened?"

**Why**: The most time-consuming part of incident response is connecting the dots between related events.

**How**:
```
Alert: "CobaltStrike beacon detected on host-42"
LLM RCA:
  → Queries process tree for host-42 (last 24h)
  → Traces parent process chain
  → Finds initial infection: user downloaded invoice.docm from email
  → Links: email → download → macro → powershell → beacon
  → Generates timeline report
```

**Effort**: 4-5 days

---

### 4. Executive Report Summarization

**What**: Given a long investigation report, generate a 1-paragraph executive summary with key findings, IOCs, and recommended actions.

**Why**: CISOs don't read 50-page forensic reports. They need bullet points.

**How**:
```bash
trace investigate --summarize <investigation-id>
# → "On Jan 15, host-42 was infected via phishing email from
#    185.220.101.24. The attacker deployed CobaltStrike beacon.
#    IOCs blocked. Host isolated. Estimated dwell time: 2 hours."
```

**Effort**: 1 day

---

### 5. Playbook Generator

**What**: Describe a scenario in natural language, get a complete playbook YAML.

**Why**: Writing playbooks in YAML by hand is error-prone. Let the LLM generate them from descriptions.

**How**:
```bash
trace playbook generate "Investigate a suspicious PowerShell invocation"
# → Generates playbook with:
#   - Collect PowerShell event logs
#   - Extract command line
#   - Decode base64
#   - Check against known bad commands
#   - Lookup hash in VT
#   - Generate report
```

**Effort**: 2-3 days

---

### 6. IOC Extraction from Unstructured Text

**What**: Paste any text (email, chat, tweet, PDF), get extracted IPs, domains, hashes, URLs with context.

**Why**: Analysts receive threat intel from many sources (email lists, Slack, Twitter). Manual extraction is slow.

**How**:
```bash
trace ioc extract "Received suspicious email from 185.220.101.24
with hash d41d8cd98f00b204e9800998ecf8427e"
# → Extracted IOCs:
#   IP: 185.220.101.24
#   MD5: d41d8cd98f00b204e9800998ecf8427e
#   Relationship: email → IP → hash
```

**Effort**: 1-2 days

---

### 7. Threat Intelligence Q&A

**What**: Ask questions about threat intel data in natural language. "What's this hash?", "Is 10.0.0.5 known for C2 activity?"

**Why**: Instead of running separate VT/OTX/AbuseIPDB lookups, ask one question and get a synthesized answer.

**How**:
```
Analyst: "what can you tell me about 185.220.101.24?"
LLM: → queries VirusTotal + OTX + AbuseIPDB simultaneously
→ synthesizes: "185.220.101.24 is a known C2 server associated with
  APT29. First seen: 2024-03. Last report: 2 days ago. 15 malware
  samples contacted this IP. Associated domains: evil.com, bad.net."
```

**Effort**: 2-3 days

---

### 8. Log Pattern Anomaly Detection

**What**: LLM analyzes log patterns and flags unusual activity that doesn't match any existing SIEM rule.

**Why**: Signature-based detection misses novel attacks. LLM can spot "weird" patterns without explicit rules.

**How**:
```bash
trace analyze patterns --since 1h
# → "Detected anomaly: PowerShell.exe making outbound HTTPS
#   connections to 3 new IPs that were never contacted before by
#   this host. This deviates from the 30-day baseline."
```

**Effort**: 3-4 days

---

### 9. Natural Language Case Search

**What**: "Show me all cases related to ransomware from last month" → returns matching cases with relevance scores.

**Why**: Current case search is basic SQL. LLM-powered semantic search finds relevant cases even when terms don't match exactly.

**How**:
```bash
trace case search "lateral movement via RDP"
# → "Found 3 related cases:
#  1. Case-42: RDP brute force from 10.0.0.50 (95% match)
#  2. Case-51: Pass-the-hash via RDP (87% match)
#  3. Case-33: BlueKeep exploitation attempt (72% match)"
```

**Effort**: 1-2 days

---

### 10. Automated Playbook Execution with LLM Decision Points

**What**: During playbook execution, LLM makes decisions at branching points instead of relying on hardcoded rules.

**Why**: Current playbooks are deterministic. LLM can adapt based on context: "if the hash is unknown AND the file is signed by Microsoft, skip analysis."

**How**: Add `llm_decision` step type to playbooks:
```yaml
steps:
  - name: classify_threat
    type: llm_decision
    prompt: "Based on these findings, is this likely malicious?"
    choices:
      malicious: run_playbook isolation_playbook
      suspicious: run_playbook deep_analysis
      benign: close_case
```

**Effort**: 2-3 days

---

## Summary

| Idea | Effort | Impact | Dependencies |
|------|--------|--------|-------------|
| 1. Alert triage | 2-3 days | High | SIEM engine |
| 2. Investigation co-pilot | 3-4 days | High | TSE query |
| 3. Root cause analysis | 4-5 days | High | Process tree + event store |
| 4. Report summarization | 1 day | Medium | Investigation manager |
| 5. Playbook generator | 2-3 days | Medium | Playbook engine |
| 6. IOC extraction | 1-2 days | Medium | None |
| 7. Threat intel Q&A | 2-3 days | Medium | VT/OTX/AbuseIPDB |
| 8. Log anomaly detection | 3-4 days | High | TSE query |
| 9. Case search | 1-2 days | Low | Case manager |
| 10. LLM playbook steps | 2-3 days | Medium | Playbook executor |

**Total: ~20-25 days of work.**
