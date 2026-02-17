#!/usr/bin/env bash
set -euo pipefail

# run_test_container_manager.sh — Build a test squashfs image with tcr-create-image,
# then run test_container_manager under valgrind.
#
# Must be run as root (mount, overlay, netns, crun all require privileges).
#
# Usage: sudo ./run_test_container_manager.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
CREATE_IMAGE="$SCRIPT_DIR/../host_tools/tcr-create-image.sh"
WORK_DIR="$BUILD_DIR/test_container_manager_work"
IMAGE_REF="docker.io/library/alpine:latest"
SQFS_FILE="$WORK_DIR/alpine_latest.sqfs"
VALGRIND_LOG="$BUILD_DIR/valgrind_container_manager.log"
IMG_ROOT="/tmp/tcr-test-cm-images"
CM_ROOT="/tmp/tcr-test-container-manager"
NAT_ROOT="/tmp/tcr-test-cm-nat"

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root (mount, overlay, netns, crun require privileges)" >&2
    exit 1
fi

if [[ ! -x "$BUILD_DIR/test_container_manager" ]]; then
    echo "error: test_container_manager not found — build it first (cmake .. && make test_container_manager)" >&2
    exit 1
fi

if ! command -v valgrind &>/dev/null; then
    echo "error: valgrind not found" >&2
    exit 1
fi

if ! command -v crun &>/dev/null; then
    echo "error: crun not found (needed for container lifecycle tests)" >&2
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

    # Kill any leftover crun containers
    for pid_file in "$CM_ROOT"/containers/*/crun.pid; do
        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file" 2>/dev/null || true)
            if [[ -n "$pid" ]]; then
                kill -9 "$pid" 2>/dev/null || true
                wait "$pid" 2>/dev/null || true
            fi
        fi
    done

    # Unmount overlay filesystems
    mount | grep "$CM_ROOT" | awk '{print $3}' | sort -r | while read -r mp; do
        umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
    done || true

    # Unmount image mounts
    mount | grep "$IMG_ROOT" | awk '{print $3}' | sort -r | while read -r mp; do
        umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
    done || true

    # Clean up network namespaces
    for ns in /var/run/netns/tcr-*; do
        if [[ -e "$ns" ]]; then
            ip netns del "$(basename "$ns")" 2>/dev/null || true
        fi
    done

    # Clean up /etc/hosts entries added by container_manager
    sed -i '/# tcr:/d' /etc/hosts 2>/dev/null || true

    rm -rf "$CM_ROOT" "$IMG_ROOT" "$NAT_ROOT"
}
trap cleanup EXIT

# Ensure clean state
rm -rf "$CM_ROOT" "$IMG_ROOT" "$NAT_ROOT"

# ── Run the test under valgrind ──────────────────────────────────────────────

echo "=== Running test_container_manager under valgrind ==="
echo "    image: $SQFS_FILE"
echo "    log:   $VALGRIND_LOG"
echo ""

valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --errors-for-leak-kinds=definite \
    --track-origins=yes \
    --trace-children=yes \
    --error-exitcode=99 \
    --log-file="$VALGRIND_LOG" \
    "$BUILD_DIR/test_container_manager" "$SQFS_FILE"

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
