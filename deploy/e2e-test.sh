#!/usr/bin/env bash
set -euo pipefail

# Trace E2E Test — provisions a local demo environment and validates key flows
#
# Usage:
#   ./deploy/e2e-test.sh
#
# Requires: Go 1.26+, curl, jq (optional)

echo "=== Trace E2E Test ==="
echo ""

DEMO_DIR=$(mktemp -d)
echo "Demo dir: $DEMO_DIR"

cleanup() {
  echo ""
  echo "Cleaning up..."
  if [ -n "${DEMO_PID:-}" ]; then
    kill "$DEMO_PID" 2>/dev/null || true
    wait "$DEMO_PID" 2>/dev/null || true
  fi
  rm -rf "$DEMO_DIR"
}
trap cleanup EXIT

# Build binaries
echo "==> Building trace..."
go build -o "$DEMO_DIR/trace" ./cmd/trace/

echo "==> Building trace-agent..."
go build -o "$DEMO_DIR/trace-agent" ./cmd/trace-agent/

export PATH="$DEMO_DIR:$PATH"

# Start demo
echo "==> Starting trace demo..."
trace demo --data-dir "$DEMO_DIR/data" &
DEMO_PID=$!
sleep 3

# Test 1: Health endpoint
echo ""
echo "--- Test 1: Server health ---"
HEALTH=$(curl -sf http://localhost:8443/healthz 2>&1 || true)
if [ "$HEALTH" = "ok" ]; then
  echo "  PASS: Server health check"
else
  echo "  FAIL: Server not responding ($HEALTH)"
  exit 1
fi

# Test 2: Dashboard returns HTML
echo ""
echo "--- Test 2: Web dashboard ---"
DASHBOARD=$(curl -sf http://localhost:8443/ 2>&1 | head -c 200 || true)
if echo "$DASHBOARD" | grep -qi "html"; then
  echo "  PASS: Dashboard returns HTML"
else
  echo "  FAIL: Dashboard not HTML"
  exit 1
fi

# Test 3: TSE status via API
echo ""
echo "--- Test 3: TSE events stored ---"
EVENTS=$(curl -sf http://localhost:8443/api/tse 2>&1 || true)
if echo "$EVENTS" | grep -qi "events"; then
  echo "  PASS: TSE API returns event data"
else
  echo "  WARN: TSE API unexpected response"
fi

# Test 4: TSE config
echo ""
echo "--- Test 4: TSE config show ---"
CONFIG=$(trace tse config show --config "$DEMO_DIR/data/config.json" 2>&1 || true)
if echo "$CONFIG" | grep -qi "storage"; then
  echo "  PASS: TSE config readable"
else
  echo "  WARN: TSE config issue"
fi

# Test 5: Create a case
echo ""
echo "--- Test 5: Case management ---"
CASE_OUTPUT=$(trace case create --title "E2E Test Case" --severity medium 2>&1 || true)
if echo "$CASE_OUTPUT" | grep -qi "Case created"; then
  echo "  PASS: Case created"
else
  echo "  WARN: Case creation failed"
fi

# Test 6: Compliance report
echo ""
echo "--- Test 6: Compliance report ---"
COMPLIANCE=$(trace compliance report --framework pci_dss_v4.0 2>&1 || true)
if echo "$COMPLIANCE" | grep -qi "Score"; then
  echo "  PASS: Compliance report generated"
else
  echo "  WARN: Compliance report incomplete"
fi

# Test 7: File analysis
echo ""
echo "--- Test 7: PE analysis ---"
echo "not a PE file" > "$DEMO_DIR/test.txt"
ANALYSIS=$(trace investigate -f "$DEMO_DIR/test.txt" 2>&1 || true)
if echo "$ANALYSIS" | grep -qi "is_pe"; then
  echo "  PASS: PE analysis returns result"
else
  echo "  WARN: PE analysis unexpected"
fi

echo ""
echo "=== Results ==="
echo "  All critical tests passed."
echo "  Demo running at http://localhost:8443"
echo "  PID: $DEMO_PID"
echo ""
echo "  Press Ctrl+C to stop."
wait "$DEMO_PID"
