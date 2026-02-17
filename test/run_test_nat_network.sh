#!/usr/bin/env bash
set -euo pipefail

# run_test_nat_network.sh — Build and run nat_network integration tests.
#
# Must be run as root (bridge/netns/nftables require privileges).
#
# Usage: sudo ./run_test_nat_network.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
VALGRIND_LOG="$BUILD_DIR/valgrind_nat_network.log"

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root (bridge/netns/nftables require privileges)" >&2
    exit 1
fi

if [[ ! -x "$BUILD_DIR/test_nat_network" ]]; then
    echo "error: test_nat_network not found — build it first:" >&2
    echo "  cd test/build && cmake .. && make test_nat_network" >&2
    exit 1
fi

if ! command -v valgrind &>/dev/null; then
    echo "warning: valgrind not found, running without memory checks" >&2
    echo ""
    echo "=== Running test_nat_network ==="
    "$BUILD_DIR/test_nat_network"
    exit $?
fi

# ── Run the test under valgrind ──────────────────────────────────────────────

echo "=== Running test_nat_network under valgrind ==="
echo "    log: $VALGRIND_LOG"
echo ""

valgrind \
    --leak-check=full \
    --errors-for-leak-kinds=all \
    --error-exitcode=99 \
    --log-file="$VALGRIND_LOG" \
    "$BUILD_DIR/test_nat_network"

EXITCODE=$?

echo ""
echo "=== Valgrind summary ==="
grep -E "ERROR SUMMARY|definitely lost|indirectly lost|possibly lost" "$VALGRIND_LOG" || true

if [[ $EXITCODE -eq 99 ]]; then
    echo ""
    echo "FAIL: valgrind detected memory errors (see $VALGRIND_LOG)"
    exit 1
elif [[ $EXITCODE -ne 0 ]]; then
    echo ""
    echo "FAIL: test exited with code $EXITCODE"
    exit $EXITCODE
fi

echo ""
echo "All tests passed (valgrind clean)."
