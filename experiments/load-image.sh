#!/bin/bash
set -euo pipefail

# load-image.sh <sqfs-file>
# Mounts a squashfs container image into data/images/<name>/
#
# This script is meant for the target device. It simply mounts the squashfs
# file — no extraction or heavy processing needed.
#
# Examples:
#   ./load-image.sh data/alpine_latest.sqfs
#   ./load-image.sh /path/to/myimage.sqfs

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGES_DIR="$SCRIPT_DIR/data/images"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <sqfs-file>"
    echo "Example: $0 data/alpine_latest.sqfs"
    exit 1
fi

SQFS_FILE="$(realpath "$1")"

if [[ ! -f "$SQFS_FILE" ]]; then
    echo "Error: File not found: $SQFS_FILE"
    exit 1
fi

# Derive image name from filename: alpine_latest.sqfs -> alpine_latest
IMAGE_NAME=$(basename "$SQFS_FILE" .sqfs)
MOUNT_DIR="$IMAGES_DIR/$IMAGE_NAME"

# Check if already mounted
if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
    echo "==> Already mounted: $MOUNT_DIR"
    echo "    To remount, first run: sudo umount $MOUNT_DIR"
    exit 0
fi

mkdir -p "$MOUNT_DIR"

echo "==> Mounting $SQFS_FILE -> $MOUNT_DIR"
sudo mount -t squashfs -o ro,loop "$SQFS_FILE" "$MOUNT_DIR"

# Verify mount and show contents
echo "==> Mounted successfully!"
echo "    Image metadata:"
cat "$MOUNT_DIR/tcr-config.json" 2>/dev/null || echo "    (no tcr-config.json found)"
echo ""
echo "    Bundle: $MOUNT_DIR/bundle"
echo ""
echo "To create a container: sudo ./create-container.sh $IMAGE_NAME"