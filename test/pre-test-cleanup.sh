#!/usr/bin/env bash
set -euo pipefail

# pre-test-cleanup.sh — Remove cached test images and test data.
#
# Run this when the image format changes (e.g. new fields in image-info.json)
# and cached squashfs images need to be rebuilt.
#
# Usage: sudo ./pre-test-cleanup.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
DATA_DIR="$SCRIPT_DIR/data"

echo "=== Removing cached test images ==="
rm -rfv "$BUILD_DIR/test_container_manager_work"
rm -rfv "$BUILD_DIR/test_crun_config_work"
rm -rfv "$BUILD_DIR/test_image_work"
rm -rfv "$BUILD_DIR/test_tcrd_work"

echo ""
echo "=== Removing test data ==="
# These may contain mount points, so unmount first if running as root
if [[ "$(id -u)" -eq 0 ]]; then
    mount | grep "$DATA_DIR" | awk '{print $3}' | sort -r | while read -r mp; do
        umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
    done || true
fi
rm -rfv "$DATA_DIR"

echo ""
echo "Done. Re-run the test scripts to rebuild images from scratch."
