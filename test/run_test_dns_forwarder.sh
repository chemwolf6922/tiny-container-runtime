#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
LISTEN_ADDR="127.0.0.1"
LISTEN_PORT="5053"
VALGRIND_LOG="$BUILD_DIR/valgrind.log"
SERVER_PID=""
PASS=0
FAIL=0

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -INT "$SERVER_PID"
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- start server under valgrind ---
echo "=== Starting test_dns_forwarder under valgrind ==="
valgrind --leak-check=full --errors-for-leak-kinds=all --error-exitcode=99 \
    --log-file="$VALGRIND_LOG" \
    "$BUILD_DIR/test_dns_forwarder" "$LISTEN_ADDR" "$LISTEN_PORT" &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FATAL: server failed to start"
    cat "$VALGRIND_LOG"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"
echo ""

# --- helper ---
check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"

    if [[ "$actual" == *"$expected"* ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        echo "    expected to contain: $expected"
        echo "    got: $actual"
        FAIL=$((FAIL + 1))
    fi
}

check_empty() {
    local desc="$1"
    local actual="$2"

    if [[ -z "$actual" ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        echo "    expected empty, got: $actual"
        FAIL=$((FAIL + 1))
    fi
}

# --- DNS tests ---
echo "=== DNS Query Tests ==="

# Test 1: local A lookup
result=$(dig @"$LISTEN_ADDR" -p "$LISTEN_PORT" tcr-test.local A +short +time=2 +tries=1 2>/dev/null)
check "local A lookup (tcr-test.local)" "10.88.0.10" "$result"

# Test 2: second local A lookup
result=$(dig @"$LISTEN_ADDR" -p "$LISTEN_PORT" tcr-web.local A +short +time=2 +tries=1 2>/dev/null)
check "local A lookup (tcr-web.local)" "10.88.0.20" "$result"

# Test 3: local A lookup is case-insensitive
result=$(dig @"$LISTEN_ADDR" -p "$LISTEN_PORT" TCR-TEST.LOCAL A +short +time=2 +tries=1 2>/dev/null)
check "case-insensitive local A lookup" "10.88.0.10" "$result"

# Test 4: AAAA for local domain should return NODATA (empty answer, no error)
result=$(dig @"$LISTEN_ADDR" -p "$LISTEN_PORT" tcr-test.local AAAA +short +time=2 +tries=1 2>/dev/null)
check_empty "AAAA for local domain returns NODATA (empty)" "$result"

# Test 5: upstream forwarding (bing.com A)
result=$(dig @"$LISTEN_ADDR" -p "$LISTEN_PORT" bing.com A +short +time=5 +tries=1 2>/dev/null)
if [[ -n "$result" ]]; then
    echo "  PASS: upstream forwarding (bing.com A) -> $result"
    PASS=$((PASS + 1))
else
    echo "  FAIL: upstream forwarding (bing.com A) returned empty"
    FAIL=$((FAIL + 1))
fi

# Test 6: upstream AAAA forwarding (may fail without IPv6 connectivity)
result=$(dig @"$LISTEN_ADDR" -p "$LISTEN_PORT" bing.com AAAA +short +time=5 +tries=1 2>/dev/null)
if [[ -n "$result" ]]; then
    echo "  PASS: upstream AAAA forwarding (bing.com) -> $result"
    PASS=$((PASS + 1))
else
    echo "  SKIP: upstream AAAA forwarding (no IPv6 connectivity)"
fi

# Test 7: unknown local domain goes upstream (should get NXDOMAIN)
result=$(dig @"$LISTEN_ADDR" -p "$LISTEN_PORT" nonexistent.invalid A +time=5 +tries=1 2>/dev/null)
check "NXDOMAIN for unknown domain" "NXDOMAIN" "$result"

echo ""

# --- stop server ---
echo "=== Stopping server (SIGINT) ==="
kill -INT "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null && SERVER_EXIT=0 || SERVER_EXIT=$?
SERVER_PID=""

echo "Server exited with code $SERVER_EXIT"
echo ""

# --- check valgrind ---
echo "=== Valgrind Report ==="
cat "$VALGRIND_LOG"
echo ""

# check for valgrind errors
if [[ $SERVER_EXIT -eq 99 ]]; then
    echo "  FAIL: valgrind detected memory errors"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: valgrind clean"
    PASS=$((PASS + 1))
fi

# check for leaks in the log
if grep -q "All heap blocks were freed" "$VALGRIND_LOG"; then
    echo "  PASS: no memory leaks"
    PASS=$((PASS + 1))
elif grep -q "definitely lost: 0 bytes" "$VALGRIND_LOG"; then
    echo "  PASS: no definite memory leaks"
    PASS=$((PASS + 1))
else
    echo "  FAIL: possible memory leaks (check valgrind log above)"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit "$FAIL"
