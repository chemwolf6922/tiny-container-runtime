#!/usr/bin/env bash
set -euo pipefail

# run_test_nat_network_manager.sh — Build and run nat_network_manager integration tests.
#
# Must be run as root (bridge/netns/nftables require privileges).
#
# Usage: sudo ./run_test_nat_network_manager.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
VALGRIND_LOG="$BUILD_DIR/valgrind_nat_network_manager.log"

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root (bridge/netns/nftables require privileges)" >&2
    exit 1
fi

if [[ ! -x "$BUILD_DIR/test_nat_network_manager" ]]; then
    echo "error: test_nat_network_manager not found — build it first:" >&2
    echo "  cd test/build && cmake .. && make test_nat_network_manager" >&2
    exit 1
fi

if ! command -v valgrind &>/dev/null; then
    echo "warning: valgrind not found, running without memory checks" >&2
    echo ""
    echo "=== Running test_nat_network_manager ==="
    "$BUILD_DIR/test_nat_network_manager"
    exit $?
fi

# ── Run the test under valgrind ──────────────────────────────────────────────

echo "=== Running test_nat_network_manager under valgrind ==="
echo "    log: $VALGRIND_LOG"
echo ""

valgrind \
    --leak-check=full \
    --errors-for-leak-kinds=all \
    --error-exitcode=99 \
    --log-file="$VALGRIND_LOG" \
    "$BUILD_DIR/test_nat_network_manager"

EXITCODE=$?

echo ""

if [[ "$EXITCODE" -eq 99 ]]; then
    echo "=== VALGRIND DETECTED MEMORY ERRORS ==="
    cat "$VALGRIND_LOG"
    exit 1
elif [[ "$EXITCODE" -ne 0 ]]; then
    echo "=== TEST FAILED (exit code $EXITCODE) ==="
    echo "--- valgrind log ---"
    cat "$VALGRIND_LOG"
    exit "$EXITCODE"
else
    echo "=== PASSED ==="
    # Show the valgrind summary line
    grep -A2 "LEAK SUMMARY" "$VALGRIND_LOG" 2>/dev/null || true
fi
