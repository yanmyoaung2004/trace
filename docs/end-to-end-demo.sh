#!/bin/bash
# Trace — End-to-End Demo Script (Linux/macOS)
# Run from the dev/ directory after building.
# Walks through installation, investigations, SIEM, and server.

set -e

EICAR_HASH="e99a18c428cb38d5f260853678922e03"
MIMIKATZ_HASH="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

echo "╔══════════════════════════════════════════════════╗"
echo "║     Trace — End-to-End Demo             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Step 0: Build
echo "▸ Step 0: Build binary"
go build -o.trace ./cmd.trace
echo "  ✓ Binary built: ..trace"
echo ""

# Step 1: Version
echo "▸ Step 1: Version"
..trace version
echo ""

# Step 2: Quick investigation
echo "▸ Step 2: Quick investigation — known malicious hash"
echo "  Running: investigate \"check hash $MIMIKATZ_HASH\""
..trace investigate "check hash $MIMIKATZ_HASH"
echo ""

# Step 3: Explicit playbook
echo "▸ Step 3: Explicit playbook — hash-lookup"
..trace investigate --playbook hash-lookup --param "hash=$EICAR_HASH"
echo ""

# Step 4: Domain reputation
echo "▸ Step 4: Domain reputation"
..trace investigate --playbook domain-reputation --param domain=evil.com
echo ""

# Step 5: History
echo "▸ Step 5: Investigation history"
..trace history
echo ""

# Step 6: File analysis
echo "▸ Step 6: File analysis with YARA"
EICAR_FILE="/tmp/inno-eicar-$$.txt"
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$EICAR_FILE"
..trace investigate --playbook file-analysis --param "path=$EICAR_FILE" --param "hash=$EICAR_HASH"
rm -f "$EICAR_FILE"
echo ""

# Step 7: SIEM test
echo "▸ Step 7: SIEM engine (quick test)"
LOG_DIR="/tmp/inno-siem-logs-$$"
mkdir -p "$LOG_DIR"

..trace serve --siem --log-dir "$LOG_DIR" --syslog-addr :0 &
SIEM_PID=$!
sleep 2

for i in 1 2 3 4 5 6; do
  echo "<34>Jul 18 12:00:00 server sshd[$i]: Failed password for root from 10.0.0.5 port 22 ssh2" >> "$LOG_DIR/auth.log"
done
echo '{"timestamp":"2026-07-18T12:00:00Z","event":"login","severity":3}' >> "$LOG_DIR/app.log"

sleep 3
echo "  ✓ SIEM alerts should have fired."

kill $SIEM_PID 2>/dev/null || true
rm -rf "$LOG_DIR"
echo ""

# Step 8: Server mode
echo "▸ Step 8: Central server"
..trace server --http-addr :9091 &
SERVER_PID=$!
sleep 2

if curl -sf http://localhost:9091/health > /dev/null 2>&1; then
  echo "  ✓ Server health check passed"
  echo "  ✓ Dashboard at http://localhost:9091"
fi

kill $SERVER_PID 2>/dev/null || true
echo ""

# Step 9: Plugin list
echo "▸ Step 9: Agent listing"
..trace plugin list
echo ""

# Step 10: Cleanup
echo "▸ Step 10: Cleanup"
rm -rf ~/.trace 2>/dev/null || true
echo ""

echo "╔══════════════════════════════════════════════════╗"
echo "║  Demo Complete!                                  ║"
echo "╚══════════════════════════════════════════════════╝"
