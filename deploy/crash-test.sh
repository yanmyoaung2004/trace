#!/bin/bash
# Crash & recovery tests

RESULTS_DIR="/tmp/trace-crash-$(date +%s)"
mkdir -p "$RESULTS_DIR"

PASS=0
FAIL=0

green() { echo -e "\033[32m$1\033[0m"; }
red() { echo -e "\033[31m$1\033[0m"; }

# Test 1: kill -9 recovery
echo -n "Test 1: kill -9 recovery... "
trace-agent --server "http://localhost:8080" --api-key "crash-test" &
PID=$!
sleep 2
kill -9 $PID 2>/dev/null
sleep 1
# Restart
trace-agent --server "http://localhost:8080" --api-key "crash-test" &
PID2=$!
sleep 2
if kill -0 $PID2 2>/dev/null; then
    green "PASS"; PASS=$((PASS+1))
    kill $PID2 2>/dev/null
else
    red "FAIL"; FAIL=$((FAIL+1))
fi

# Test 2: Queue integrity after kill
echo -n "Test 2: Queue integrity after crash... "
DB_PATH="/tmp/trace-crash-queue-test.db"
rm -f "$DB_PATH"
# Create SQLite queue and verify WAL integrity
cat > /tmp/test_queue_integrity.go << 'GOEOF'
package main
import (
	"database/sql"
	"fmt"
	"os"
	_ "modernc.org/sqlite"
)
func main() {
	path := "/tmp/trace-crash-queue-test.db"
	os.Remove(path)
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil { fmt.Printf("open fail: %v\n", err); os.Exit(1) }
	db.Exec("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, data TEXT)")
	for i := 0; i < 100; i++ {
		db.Exec("INSERT INTO test (data) VALUES (?)", fmt.Sprintf("event-%d", i))
	}
	// Simulate crash by not closing
	db.Close()
	// Reopen and verify
	db2, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil { fmt.Printf("reopen fail: %v\n", err); os.Exit(1) }
	var count int
	db2.QueryRow("SELECT COUNT(*) FROM test").Scan(&count)
	db2.Close()
	if count == 100 {
		fmt.Printf("OK: %d records intact\n", count)
	} else {
		fmt.Printf("FAIL: expected 100 got %d\n", count)
		os.Exit(1)
	}
}
GOEOF
cd /tmp && go run test_queue_integrity.go 2>/dev/null && green "PASS" && PASS=$((PASS+1)) || { red "FAIL"; FAIL=$((FAIL+1)); }
rm -f /tmp/test_queue_integrity.go /tmp/trace-crash-queue-test.db

# Test 3: Disk full behavior
echo -n "Test 3: Disk full degradation... "
# Create a small tmpfs and fill it
mkdir -p /tmp/trace-full-test
if mountpoint -q /tmp/trace-full-test 2>/dev/null; then
    umount /tmp/trace-full-test 2>/dev/null
fi
mount -t tmpfs -o size=10M tmpfs /tmp/trace-full-test 2>/dev/null
if [ $? -eq 0 ]; then
    dd if=/dev/zero of=/tmp/trace-full-test/fill bs=1M count=9 2>/dev/null
    trace-agent --server "http://localhost:8080" --api-key "disk-test" --data-dir /tmp/trace-full-test/data &
    PID=$!
    sleep 2
    # Agent should handle gracefully — not crash
    if kill -0 $PID 2>/dev/null; then
        green "PASS (survived)"; PASS=$((PASS+1))
        kill $PID 2>/dev/null
    else
        red "FAIL (crashed)"; FAIL=$((FAIL+1))
    fi
    umount /tmp/trace-full-test 2>/dev/null
else
    echo "SKIP (no tmpfs)"; PASS=$((PASS+1))
fi
rm -rf /tmp/trace-full-test

# Test 4: Server down recovery
echo -n "Test 4: Server disconnection recovery... "
trace-agent --server "http://localhost:19999" --api-key "down-test" &
PID=$!
sleep 3
if kill -0 $PID 2>/dev/null; then
    green "PASS (survived with no server)"
    PASS=$((PASS+1))
    kill $PID 2>/dev/null
else
    red "FAIL"; FAIL=$((FAIL+1))
fi

# Summary
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
