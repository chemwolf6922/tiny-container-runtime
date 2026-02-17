#!/usr/bin/env bash
set -euo pipefail

# run_test_crun_config.sh — Build a test squashfs image with tcr-create-image,
# then run test_crun_config under valgrind.
#
# Must be run as root (image_manager needs mount/umount privileges).
#
# Usage: sudo ./run_test_crun_config.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
CREATE_IMAGE="$SCRIPT_DIR/../host_tools/tcr-create-image.sh"
WORK_DIR="$BUILD_DIR/test_crun_config_work"
IMAGE_REF="docker.io/library/alpine:latest"
SQFS_FILE="$WORK_DIR/alpine_latest.sqfs"
VALGRIND_LOG="$BUILD_DIR/valgrind_crun_config.log"
DATA_DIR="$SCRIPT_DIR/data"
mkdir -p "$DATA_DIR"
IMG_ROOT="$DATA_DIR/tcr-test-crun-config"

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root (mount/umount require privileges)" >&2
    exit 1
fi

if [[ ! -x "$BUILD_DIR/test_crun_config" ]]; then
    echo "error: test_crun_config not found — build it first (cmake .. && make test_crun_config)" >&2
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

# ── Cleanup function ────────────────────────────────────────────────────────

cleanup() {
    echo "=== Cleaning up ==="
    # The test binary cleans up via image_manager_free(_, true) which unmounts,
    # but if the test crashed we need to clean up manually.
    mount | grep "$IMG_ROOT" | awk '{print $3}' | sort -r | while read -r mp; do
        umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
    done || true
    rm -rf "$IMG_ROOT"
}
trap cleanup EXIT

# Ensure clean state
rm -rf "$IMG_ROOT"

# ── Run the test under valgrind ──────────────────────────────────────────────

echo "=== Running test_crun_config under valgrind ==="
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
    "$BUILD_DIR/test_crun_config" "$SQFS_FILE"

TEST_EXIT=$?

echo ""
echo "=== Valgrind summary ==="
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
