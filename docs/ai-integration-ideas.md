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

## 11. AI Deception — Generate Decoy Assets

**What**: LLM generates realistic decoy files, credentials, and documents to trap attackers. When an attacker touches a decoy, an alert fires immediately.

**Why**: Moving from reactive to proactive defense. Decoys catch attackers early in the kill chain (reconnaissance phase).

**How**:
```bash
trace decoy generate --type honey_file --count 20
# → LLM generates 20 realistic-looking documents named:
#   - passwords-prod.xlsx, vpn-config.ovpn, ssh-keys-backup.tar.gz
# → Deploys to specified directories via agent
# → Any read/access triggers critical alert
```

**Effort**: 3-4 days

---

## 12. Automated Detection Rule Generation

**What**: Describe a threat in natural language, LLM generates a working SIEM detection rule (Sigma or Trace format) with the right logic, severity, and MITRE mapping.

**Why**: Writing good detection rules requires deep expertise. LLM lets any analyst create rules from threat intel reports.

**How**:
```bash
trace rule generate "detect powershell downloading and executing a payload in memory"
# → Generates:
# rule:
#   title: PowerShell Memory Payload Download & Execute
#   description: Detects PowerShell downloading content and executing
#   logsource: process
#   detection:
#     selection:
#       Image: '*powershell.exe'
#       CommandLine: '*WebClient*DownloadString*Invoke*'
#     condition: selection
#   mitre: T1059.001
#   severity: high
```

**Effort**: 2-3 days

---

## 13. Conversational Incident Response Playbook

**What**: A guided chat interface that walks analysts through incident response step by step, asking questions and suggesting actions based on playbook context.

**Why**: Junior analysts don't know the IR process. The LLM acts as a senior mentor guiding them through containment, eradication, and recovery.

**How**:
```
LLM: "Alert: Possible ransomware on host-42. Shall I isolate the host?"
Analyst: "Yes"
LLM: "Host isolated. I can see encryption activity on:
  - C:\Users\*.docx (locked)
  - \\server\share\*.xlsx (locked)
  Do you want to:
  1. Run the ransomware decryption playbook
  2. Collect forensic snapshot
  3. Both"
Analyst: "Both"
LLM: "Forensic snapshot saved. Running decryption playbook..."
```

**Effort**: 4-5 days

---

## 14. Multi-Agent Investigation Team

**What**: Instead of one LLM, spawn multiple specialized AI agents that work in parallel on different parts of an investigation and report back to a coordinator agent.

**Why**: Complex investigations have many parallel workstreams (hash lookup, log analysis, timeline, threat intel). A single LLM is sequential and slow.

**How**:
```
Coordinator Agent receives alert: "Suspicious outbound connection to known C2"
  → Spawns:
    → Agent 1: DNS log analyst — queries DNS logs for C2 domain
    → Agent 2: Process analyst — traces process tree on affected host
    → Agent 3: Threat intel analyst — researches C2 IP in VT/OTX
    → Agent 4: Timeline analyst — builds event timeline
  → Each agent works in parallel, reports findings
  → Coordinator merges results into single report
```

**Effort**: 5-7 days

---

## 15. Autonomous Threat Hunting

**What**: LLM generates hunting hypotheses based on the organization's environment, runs queries automatically, and reports findings — no human input required.

**Why**: Most organizations don't hunt proactively because it requires senior analysts. An AI hunter runs 24/7.

**How**:
```bash
trace hunt auto --schedule "0 */6 * * *"
# → Every 6 hours, LLM:
#   1. Reviews recent events and environment context
#   2. Generates 3 hunting hypotheses (e.g., "Check for unusual
#      PowerShell usage on domain controllers")
#   3. Runs TSE queries for each hypothesis
#   4. Reports findings or "nothing suspicious found"
```

**Effort**: 4-5 days

---

## 16. Cross-Language Script Deobfuscation

**What**: Paste obfuscated PowerShell, Python, or JavaScript — LLM deobfuscates and explains what the script does in plain English.

**Why**: Malware authors heavily obfuscate scripts. Manual deobfuscation takes hours. LLM does it in seconds.

**How**:
```bash
trace deobfuscate "powershell -e JABzAD0ATgBlAHcALQBPAGIAagBlAGM..."
# → Deobfuscated:
#   This PowerShell script downloads a payload from
#   http://evil.com/payload.exe, saves it to
#   C:\Users\Public\svchost.exe, and executes it.
#   It also creates persistence via Run registry key.
```

**Effort**: 2-3 days

---

## 17. Automated Evidence Package Generation

**What**: Given a case ID, LLM automatically collects all relevant evidence (logs, files, screenshots, timeline), organizes them, and generates a court-admissible evidence package with chain-of-custody documentation.

**Why**: Preparing evidence for legal/HR action is tedious and error-prone. LLM automates the entire workflow.

**How**:
```bash
trace evidence package --case case-42 --format zip
# → Generated:
#   case-42-evidence.zip/
#     ├── timeline.json          # All relevant events sorted by time
#     ├── iocs.csv               # All extracted IOCs
#     ├── forensic_snapshot/     # Process + network + file snapshots
#     ├── report.pdf             # Executive summary + technical details
#     └── chain_of_custody.txt   # Signed audit trail
```

**Effort**: 2-3 days

---

## 18. LLM-Powered SIEM Rule Testing & Tuning

**What**: Before deploying a SIEM rule, LLM tests it against historical data, estimates false positive rate, suggests threshold adjustments, and validates the rule won't flood the alert queue.

**Why**: Bad rules cause alert fatigue. LLM catches issues before deployment.

**How**:
```bash
trace rule test --rule-file new-rule.yaml
# → LLM Analysis:
#   "This rule would have fired 1,247 times in the last 30 days.
#    False positive rate estimate: 78%. Suggestions:
#    1. Add exclusion for 'C:\Program Files\*' paths
#    2. Increase threshold to 5 events in 10 minutes
#    3. Filter out processes signed by Microsoft
#    Estimated FP rate after fixes: 12%"
```

**Effort**: 2-3 days

---

## 19. Security Posture Improvement Suggestions

**What**: LLM analyzes the environment's security gaps (missing rules, unpatched systems, misconfigurations found by SCA) and generates prioritized improvement recommendations with step-by-step remediation.

**Why**: SCA reports tell you what's wrong but not how to fix it in priority order. LLM bridges the gap.

**How**:
```bash
trace posture assess --framework pci_dss_v4.0
# → LLM:
#   "Your PCI DSS score is 86%. Top 3 quick wins:
#    1. Enable MFA on 12 admin accounts (control 8.3.2)
#       → Gains: +7% score, Est. time: 30 minutes
#    2. Patch 5 critical Apache servers (control 6.2)
#       → Gains: +4% score, Est. time: 2 hours
#    3. Remove default accounts on 3 Windows servers (control 2.2.4)
#       → Gains: +3% score, Est. time: 15 minutes"
```

**Effort**: 2-3 days

---

## 20. Multi-Modal File Analysis

**What**: Use vision-capable LLMs to analyze images, screenshots, and PDFs submitted as case evidence. Extract text, detect forgeries, identify embedded metadata.

**Why**: Analysts receive screenshots and PDFs as evidence. Current analysis is manual. Vision LLM automates it.

**How**:
```bash
trace analyze image --file suspicious_email.png
# → LLM Vision: "This email screenshot shows:
#   - From: hr@evil-phish.com (forged display name)
#   - Attachment: invoice.docm (macro-enabled)
#   - Urgency tactics: 'Immediate action required'
#   - Reply-to differs from from-address
#   Verdict: Phishing attempt (confidence: 96%)"
```

**Effort**: 2-3 days

---

## Summary

| Idea | Effort | Impact | Type |
|------|--------|--------|------|
| 1. Alert triage | 2-3d | High | Triage |
| 2. Investigation co-pilot | 3-4d | High | Investigation |
| 3. Root cause analysis | 4-5d | High | Investigation |
| 4. Report summarization | 1d | Medium | Reporting |
| 5. Playbook generator | 2-3d | Medium | Automation |
| 6. IOC extraction | 1-2d | Medium | Intel |
| 7. Threat intel Q&A | 2-3d | Medium | Intel |
| 8. Log anomaly detection | 3-4d | High | Detection |
| 9. Case search | 1-2d | Low | UX |
| 10. LLM playbook steps | 2-3d | Medium | Automation |
| 11. AI deception | 3-4d | High | Proactive |
| 12. Rule generation | 2-3d | High | Detection |
| 13. Conversational IR | 4-5d | Medium | Response |
| 14. Multi-agent team | 5-7d | High | Architecture |
| 15. Autonomous hunting | 4-5d | High | Proactive |
| 16. Script deobfuscation | 2-3d | Medium | Analysis |
| 17. Evidence packaging | 2-3d | Medium | Case |
| 18. Rule testing | 2-3d | Medium | Detection |
| 19. Posture improvement | 2-3d | Medium | Compliance |
| 20. Multi-modal analysis | 2-3d | Medium | Analysis |

**Total: ~50-65 days of work. Pick what excites you most.**
