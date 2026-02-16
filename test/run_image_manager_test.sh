#!/usr/bin/env bash
set -euo pipefail

# run_image_manager_test.sh — Build a test squashfs image with tcr-create-image,
# then run test_image_manager under valgrind.
#
# Must be run as root (the test needs mount/umount privileges).
#
# Usage: sudo ./run_image_manager_test.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
CREATE_IMAGE="$SCRIPT_DIR/../host_tools/tcr-create-image.sh"
WORK_DIR="$BUILD_DIR/test_image_work"
IMAGE_REF="docker.io/library/alpine:latest"
SQFS_FILE="$WORK_DIR/alpine_latest.sqfs"
VALGRIND_LOG="$BUILD_DIR/valgrind_image_manager.log"

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root (mount/umount require privileges)" >&2
    exit 1
fi

if [[ ! -x "$BUILD_DIR/test_image_manager" ]]; then
    echo "error: test_image_manager not found — build it first (cmake .. && make test_image_manager)" >&2
    exit 1
fi

if ! command -v valgrind &>/dev/null; then
    echo "error: valgrind not found" >&2
    exit 1
fi

# ── Prepare the test image ──────────────────────────────────────────────────

if [[ -f "$SQFS_FILE" ]]; then
    echo "=== Using existing test image: $SQFS_FILE ==="
else
    echo "=== Creating test image from $IMAGE_REF ==="
    mkdir -p "$WORK_DIR"
    bash "$CREATE_IMAGE" -o "$SQFS_FILE" -w "$WORK_DIR/tcr-build" -f "$IMAGE_REF"
    echo ""
fi

if [[ ! -f "$SQFS_FILE" ]]; then
    echo "error: failed to create test image" >&2
    exit 1
fi

# ── Run the test under valgrind ──────────────────────────────────────────────

echo "=== Running test_image_manager under valgrind ==="
echo "    image: $SQFS_FILE"
echo "    log:   $VALGRIND_LOG"
echo ""

valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --errors-for-leak-kinds=all \
    --track-origins=yes \
    --error-exitcode=99 \
    --log-file="$VALGRIND_LOG" \
    "$BUILD_DIR/test_image_manager" "$SQFS_FILE"

TEST_EXIT=$?

echo ""
echo "=== Valgrind summary ==="
# Print the summary section from the log
sed -n '/HEAP SUMMARY/,$ p' "$VALGRIND_LOG"
echo ""

if [[ $TEST_EXIT -eq 99 ]]; then
    echo "FAIL: valgrind detected memory errors (see $VALGRIND_LOG)"
    exit 1
elif [[ $TEST_EXIT -ne 0 ]]; then
    echo "FAIL: test exited with code $TEST_EXIT"
    cat "$VALGRIND_LOG"
    exit 1
else
    echo "PASS: all tests passed, no memory errors"
fi
