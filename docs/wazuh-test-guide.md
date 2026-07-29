# Wazuh Feature Comparison — Test Guide

## Overview

This guide shows how to test each Wazuh-like capability in Trace.
Start with `trace demo` to get a running environment, then run each test.

---

## 1. Log Collection (Wazuh → syslog/file)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| Syslog collector | `trace serve --siem --syslog-addr :514` | Send a test syslog message and verify it's received |

```bash
# Start SIEM with syslog listener
trace serve --siem --syslog-addr :514

# From another terminal, send a test syslog message
echo "Sep 27 10:00:00 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2" | nc -u localhost 514

# Agent log collector (Linux)
# Agent tails /var/log/auth.log, /var/log/syslog
trace-agent --config agent.yaml
# Events appear in web dashboard at /alerts
```

---

## 2. File Integrity Monitoring (Wazuh → FIM)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| FIM | Agent FIM monitor watches file changes | Create or modify a watched file and verify event |

```bash
# Start demo with agent
trace demo --port 9999

# Create a file in the watched directory
echo "test content" > C:\Temp\trace-demo-test\test-file.txt
# or on Linux:
echo "test content" > /tmp/test-file.txt

# Check the dashboard at http://localhost:9999
# Events should appear as "file_create" type
```

---

## 3. Vulnerability Detection (Wazuh → Vulnerability detector)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| Vulnerability detector | Agent vuln scanner + builtin CVE database | Agent scans installed packages, matches against CVEs |

```bash
# Start agent with vuln scanning enabled (default)
trace-agent --config agent.yaml
# Agent logs: [vuln] scanning packages...

# Query vuln status
trace-agent --status
# Or via server API
curl http://localhost:9999/api/v1/edr/vuln/feed
```

---

## 4. Compliance / SCA (Wazuh → Security Configuration Assessment)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| SCA | Compliance reporting with CIS benchmarks | Generate a compliance report |

```bash
# List available frameworks
trace compliance list

# Generate a compliance report
trace compliance report --framework pci_dss_v4.0
# Output: Score: 86% (12/14 controls passed)

# Export to HTML
trace compliance report --framework pci_dss_v4.0 --output report.html
start report.html

# Check a specific control
trace compliance assess --framework pci_dss_v4.0 --control 8.2.1
```

---

## 5. Malware Detection (Wazuh → YARA + Anti-malware)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| YARA | Built-in YARA rules (17) + custom `.yar` files | Scan files with YARA |

```bash
# Scan a file with YARA
trace investigate -f /path/to/file.exe
# Shows: YARA matches, PE metadata, hash lookup

# Add custom YARA rules
mkdir -p ~/.trace/yara
cat > ~/.trace/yara/my_rules.yar << 'EOF'
rule MyCustomRule {
  meta:
    description = "Custom test rule"
  strings:
    $test = "suspicious" nocase
  condition:
    $test
}
EOF

# Scan again — custom rules are merged with built-in
trace investigate -f suspicious.txt

# Hash lookup (VirusTotal if API key configured)
# Set TRACE_VT_API_KEY or add to config
trace investigate --playbook hash-lookup --param hash=d41d8cd98f00b204e9800998ecf8427e
```

---

## 6. Active Response (Wazuh → Active response)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| Active response | Response actions via EDR agent | Dispatch action to agent |

```bash
# List registered agents
trace edr list

# Dispatch a response action
trace edr dispatch <agent-id> kill_process --pid 1234
trace edr dispatch <agent-id> quarantine_file --path /tmp/malware.exe
trace edr dispatch <agent-id> block_ip --ip 10.0.0.5
trace edr dispatch <agent-id> run_script --script "echo 'cleanup done'"

# View action status
trace edr events <agent-id>
```

---

## 7. Security Events (Wazuh → Event correlation)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| Event correlation | 464 SIEM rules with MITRE mapping | Trigger a rule and verify alert |

```bash
# Start SIEM
trace serve --siem

# Feed test data
echo "sshd[1234]: Failed password for root from 10.0.0.5" | trace serve --siem-stdin

# Check alerts
trace case list
# Or web dashboard at http://localhost:8443/alerts
```

---

## 8. Central Management (Wazuh → Wazuh server/dashboard)

| Wazuh | Trace | How to test |
|-------|-------|-------------|
| Server/Dashboard | Web dashboard + sync server | Open browser and explore |

```bash
# Start server
trace server --http-addr :8443

# Open web UI
start http://localhost:8443

# Available pages:
# /         - Dashboard with stats, charts, investigation list
# /alerts   - SIEM alerts with severity filter
# /cases    - Case management
# /correlations - Cross-node IOC correlations
# /api/tse  - TSE storage engine metrics
```

---

## Quick Test Script

```bash
# Run this to test all major Wazuh-like features in one go
echo "=== 1. SIEM Alert ==="
trace compliance report --framework pci_dss_v4.0
echo ""

echo "=== 2. PE Analysis ==="
trace investigate -f C:\Windows\System32\notepad.exe
echo ""

echo "=== 3. YARA Scan ==="
echo test > /tmp/eicar.txt
trace investigate -f /tmp/eicar.txt
echo ""

echo "=== 4. Case Management ==="
trace case list
echo ""

echo "=== 5. TSE Storage ==="
trace tse status --storage-path ./data/tse
echo ""

echo "=== 6. Shell Completion ==="
trace completion bash | head -3
```
