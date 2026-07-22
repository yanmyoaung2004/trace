#!/bin/bash
# Soak test: Run agent for 24h on real system, collect metrics
# Usage: ./deploy/soak-test.sh [duration] [server-url] [api-key]

DURATION="${1:-86400}"
SERVER="${2:-http://localhost:8080}"
API_KEY="${3:-test-key}"
RESULTS_DIR="/tmp/trace-soak-$(date +%s)"
AGENT_PID=""

mkdir -p "$RESULTS_DIR"
echo "=== Trace Agent Soak Test ===" > "$RESULTS_DIR/summary.txt"
echo "Start: $(date -Iseconds)" >> "$RESULTS_DIR/summary.txt"
echo "Duration: ${DURATION}s" >> "$RESULTS_DIR/summary.txt"
echo "Server: $SERVER" >> "$RESULTS_DIR/summary.txt"
echo "" >> "$RESULTS_DIR/summary.txt"

cleanup() {
    echo "Cleaning up..."
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
    echo "End: $(date -Iseconds)" >> "$RESULTS_DIR/summary.txt"
    wait
}
trap cleanup EXIT INT TERM

# Start agent
echo "Starting agent..."
trace-agent --server "$SERVER" --api-key "$API_KEY" &
AGENT_PID=$!
sleep 2

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "FAIL: Agent failed to start" | tee -a "$RESULTS_DIR/summary.txt"
    exit 1
fi
echo "Agent PID: $AGENT_PID" >> "$RESULTS_DIR/summary.txt"

# Monitoring loop
INTERVAL=60
ELAPSED=0
MAX_MEM=0
MAX_CPU=0
EVENT_COUNT=0
CRASH_COUNT=0
LAST_RSS=0

while [ "$ELAPSED" -lt "$DURATION" ]; do
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        echo "CRASH at ${ELAPSED}s" >> "$RESULTS_DIR/crashes.txt"
        CRASH_COUNT=$((CRASH_COUNT + 1))
        trace-agent --server "$SERVER" --api-key "$API_KEY" &
        AGENT_PID=$!
        sleep 2
    fi

    # Collect metrics
    RSS=$(ps -o rss= -p "$AGENT_PID" 2>/dev/null | tr -d ' ')
    CPU=$(ps -o %cpu= -p "$AGENT_PID" 2>/dev/null | tr -d ' ')
    THREADS=$(ls /proc/$AGENT_PID/task 2>/dev/null | wc -l)
    HANDLES="N/A"
    if [ -f /proc/$AGENT_PID/status ]; then
        HANDLES=$(awk '/FDSize/{print $2}' /proc/$AGENT_PID/status)
    fi

    [ -n "$RSS" ] && [ "$RSS" -gt "$MAX_MEM" ] && MAX_MEM=$RSS
    [ -n "$CPU" ] && [ "$(echo "$CPU > $MAX_CPU" | bc 2>/dev/null)" = "1" ] && MAX_CPU=$CPU

    echo "t=${ELAPSED}s rss=${RSS}kB cpu=${CPU}% threads=${THREADS} handles=${HANDLES}" >> "$RESULTS_DIR/metrics.txt"

    ELAPSED=$((ELAPSED + INTERVAL))
    sleep "$INTERVAL"
done

# Summary
echo "" >> "$RESULTS_DIR/summary.txt"
echo "=== Results ===" >> "$RESULTS_DIR/summary.txt"
echo "Duration completed: ${DURATION}s" >> "$RESULTS_DIR/summary.txt"
echo "Max RSS: ${MAX_MEM}kB" >> "$RESULTS_DIR/summary.txt"
echo "Max CPU: ${MAX_CPU}%" >> "$RESULTS_DIR/summary.txt"
echo "Crashes: ${CRASH_COUNT}" >> "$RESULTS_DIR/summary.txt"

# Check thresholds
PASS=1
if [ "$MAX_MEM" -gt 262144 ]; then echo "FAIL: RSS exceeded 256MB" >> "$RESULTS_DIR/summary.txt"; PASS=0; fi
if [ "$CRASH_COUNT" -gt 0 ]; then echo "FAIL: Agent crashed" >> "$RESULTS_DIR/summary.txt"; PASS=0; fi
if [ "$PASS" = "1" ]; then echo "PASS: All thresholds met" >> "$RESULTS_DIR/summary.txt"; fi

cat "$RESULTS_DIR/summary.txt"
exit $([ "$PASS" = "1" ] && echo 0 || echo 1)
