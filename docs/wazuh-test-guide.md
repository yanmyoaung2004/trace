# Wazuh-Like Multi-Computer Test Guide

## Scenario

```
Machine A (Server) — 192.168.1.100
  └─ Runs: trace server (central manager)
  └─ Ports: :8080 (HTTP API), :8443 (dashboard), :514 (syslog)

Machine B (Agent)  — 192.168.1.101  
  └─ Runs: trace-agent (monitored endpoint)
  └─ Connects to: Machine A:8080
```

---

## Step 0: Build the binaries

Run these on both machines (or build once and copy):

```bash
# Build server binary
cd dev
go build -o trace-server ./cmd/trace/

# Build agent binary
go build -o trace-agent ./cmd/trace-agent/

# Copy to both machines
scp trace-server user@192.168.1.100:~/
scp trace-agent user@192.168.1.101:~/
```

---

## Step 1: Start the server (Machine A)

```bash
# Start central server with web dashboard
./trace-server server --http-addr :8080

# Or with TLS + TSE storage
./trace-server server \
  --http-addr :8443 \
  --tse-storage-path ./data/tse

# Verify it's running
curl http://localhost:8080/healthz
# → ok
```

---

## Step 2: Install and connect the agent (Machine B)

```bash
# On Machine B, start agent pointing to Machine A
./trace-agent \
  --server http://192.168.1.100:8080 \
  --verbose
```

The agent auto-registers with the server. Watch the server logs on Machine A:
```
[trace-agent] registered with server (id: abc123...)
```

**Verify connection** — on Machine A:
```bash
curl http://localhost:8080/api/v1/edr/agents
# → [{"id":"abc...","hostname":"machine-b","status":"active",...}]

# Or via CLI
./trace-server edr list
```

---

## Step 3: Test — Event Collection

### File monitoring

On Machine B, create a file:
```bash
echo "suspicious content" > /tmp/test-file.txt
```

On Machine A, check the events:
```bash
curl "http://localhost:8080/api/v1/edr/events?agent_id=abc&limit=5"
```

### Process monitoring

On Machine B, run something:
```bash
whoami
ping 8.8.8.8
```

On Machine A, view process events:
```bash
./trace-server edr events <agent-id> --type process_create
```

---

## Step 4: Test — YARA Malware Detection

On Machine B, the agent automatically YARA-scans files.
Create a file that matches a built-in YARA rule:

```bash
echo "Invoke-Expression (New-Object Net.WebClient).DownloadString" > /tmp/ps_script.ps1
```

The YARA rule `Suspicious_PowerShell` will match this. After the agent's scan interval:

On Machine A:
```bash
./trace-server edr events <agent-id> --type yara_match
```

---

## Step 5: Test — Vulnerability Scanning

On Machine B, the agent scans installed packages every 6 hours.
Trigger an immediate scan (or wait):

On Machine A, check for vuln events:
```bash
curl "http://localhost:8080/api/v1/edr/vulns?agent_id=abc&min_severity=7"

# Or view the built-in CVE feed
curl http://localhost:8080/api/v1/edr/vuln/feed
```

---

## Step 6: Test — Active Response

From Machine A, dispatch a response action to Machine B:

```bash
# List agents to get the ID
./trace-server edr list

# Block an IP
./trace-server edr dispatch <agent-id> block_ip --ip 185.220.101.24

# Kill a process
./trace-server edr dispatch <agent-id> kill_process --pid 1234

# Run a script
./trace-server edr dispatch <agent-id> run_script --script "echo 'cleanup done' > /tmp/response.log"

# Check action result
./trace-server edr events <agent-id> --type action_result
```

---

## Step 7: Test — Configuration Management

Push config from server to agent:

```bash
# On Machine A, set agent defaults
curl -X PUT http://localhost:8080/api/v1/edr/config \
  -H "Authorization: Bearer <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"monitor_process":true,"monitor_file":true,"vuln_scan_enabled":true}'

# Agent fetches this within 30 minutes, or on restart
```

---

## Step 8: Test — Agent Auto-Update

```bash
# On Machine A, build and stage a new agent version
./trace-server build agent --upload ./updates

# Agent checks for updates every 6 hours
# To force an immediate check, restart the agent on Machine B
```

---

## Step 9: Web Dashboard

Open a browser on any machine and navigate to:
```
http://192.168.1.100:8080
```

You'll see:
- Investigation list
- Alert dashboard charts
- Connected agents
- TSE storage metrics
- Cases and correlations

---

## Full End-to-End Test Script

Run this on Machine A to verify everything is connected:

```bash
echo "=== Wazuh-Like Test Suite ==="
echo ""

echo "1. Server health..."
curl -sf http://localhost:8080/healthz && echo " ✓"

echo "2. Connected agents..."
curl -sf http://localhost:8080/api/v1/edr/agents | grep -c "hostname"
echo " agent(s) connected"

echo "3. Agent events..."
AGENT_ID=$(curl -sf http://localhost:8080/api/v1/edr/agents | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
curl -sf "http://localhost:8080/api/v1/edr/events?agent_id=$AGENT_ID&limit=3" | grep -c "event_type"
echo " event types found"

echo "4. Compliance report..."
./trace-server compliance report --framework pci_dss_v4.0 | grep "Score"

echo "5. CVE feed..."
curl -sf http://localhost:8080/api/v1/edr/vuln/feed | grep -c "cve_id"
echo " CVEs in feed"

echo "6. Dashboard..."
curl -sf http://localhost:8080/ | head -1 | grep -c html
echo " HTML pages served"

echo ""
echo "=== All tests complete ==="
```
