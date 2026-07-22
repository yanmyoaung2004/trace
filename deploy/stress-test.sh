#!/bin/bash
# Volume & stress test
# Generates realistic workloads to test agent throughput

RESULTS_DIR="/tmp/trace-stress-$(date +%s)"
mkdir -p "$RESULTS_DIR"

echo "=== Stress Test ===" > "$RESULTS_DIR/summary.txt"
echo "Start: $(date -Iseconds)" >> "$RESULTS_DIR/summary.txt"

cleanup() { echo "Cleaning up..."; }
trap cleanup EXIT INT TERM

# Test 1: Process burst
echo ""
echo "=== Test 1: Process burst (5000 short-lived processes) ==="
START=$(date +%s%N)
for i in $(seq 1 5000); do
    /bin/true &
    if [ $((i % 500)) -eq 0 ]; then
        wait
        echo "  burst: ${i}/5000 processes created"
    fi
done
wait
END=$(date +%s%N)
BURST_TIME=$(( (END - START) / 1000000 ))
echo "burst: 5000 processes in ${BURST_TIME}ms" >> "$RESULTS_DIR/summary.txt"

# Test 2: File storm
echo ""
echo "=== Test 2: File storm (10000 files in /tmp) ==="
TMPDIR="/tmp/trace-storm-$$"
mkdir -p "$TMPDIR"
START=$(date +%s%N)
for i in $(seq 1 10000); do
    dd if=/dev/urandom of="$TMPDIR/file-$i.bin" bs=1024 count=1 2>/dev/null
    if [ $((i % 1000)) -eq 0 ]; then
        echo "  files: ${i}/10000 created"
    fi
done
rm -rf "$TMPDIR"
END=$(date +%s%N)
STORM_TIME=$(( (END - START) / 1000000 ))
echo "files: 10000 files in ${STORM_TIME}ms" >> "$RESULTS_DIR/summary.txt"

# Test 3: Network sweep (simulated)
echo ""
echo "=== Test 3: Connection burst (1000 simulated connections) ==="
START=$(date +%s%N)
for i in $(seq 1 1000); do
    curl -s --connect-timeout 1 "http://192.0.2.${i}:80/" >/dev/null 2>&1 &
    if [ $((i % 200)) -eq 0 ]; then
        wait
        echo "  connections: ${i}/1000 attempted"
    fi
done
wait
END=$(date +%s%N)
NET_TIME=$(( (END - START) / 1000000 ))
echo "network: 1000 connections in ${NET_TIME}ms" >> "$RESULTS_DIR/summary.txt"

# Test 4: Fork bomb detection
echo ""
echo "=== Test 4: Fork bomb (ulimit-protected) ==="
START=$(date +%s%N)
FORK_COUNT=0
for i in $(seq 1 200); do
    (sleep 5) &
    FORK_COUNT=$((FORK_COUNT + 1))
done
FORK_TIME=$(( ($(date +%s%N) - START) / 1000000 ))
echo "fork: ${FORK_COUNT} children in ${FORK_TIME}ms" >> "$RESULTS_DIR/summary.txt"
wait

# Results
echo ""
echo "=== Results ===" >> "$RESULTS_DIR/summary.txt"
cat "$RESULTS_DIR/summary.txt"
echo ""
echo "Results saved to $RESULTS_DIR"
echo "Compare with agent metrics: trace-agent --status"
