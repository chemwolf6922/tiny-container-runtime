#!/bin/bash
set -euo pipefail

# run-container.sh <container-id>
# Runs a prepared container with crun.
# Config and command are set by create-container.sh beforehand.
#
# Examples:
#   ./run-container.sh alpine_latest-a1b2c3d4
#   sudo ./run-container.sh myshell

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINERS_DIR="$SCRIPT_DIR/data/containers"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <container-id>"
    echo ""
    echo "Available containers:"
    ls "$CONTAINERS_DIR" 2>/dev/null || echo "  (none)"
    exit 1
fi

CONTAINER_ID="$1"
CONTAINER_DIR="$CONTAINERS_DIR/$CONTAINER_ID"
CONTAINER_CONFIG="$CONTAINER_DIR/config.json"
CONTAINER_META="$CONTAINER_DIR/tcr-container.json"

if [[ ! -f "$CONTAINER_CONFIG" ]]; then
    echo "Error: Container '$CONTAINER_ID' not found"
    echo "Run create-container.sh first."
    exit 1
fi

# Read the image bundle path from metadata
BUNDLE_PATH=$(jq -r '.imageBundlePath' "$CONTAINER_META")

if ! sudo test -d "$BUNDLE_PATH/rootfs"; then
    echo "Error: Image rootfs not found at $BUNDLE_PATH/rootfs"
    echo "Is the image still mounted? Check load-image.sh."
    exit 1
fi

echo "==> Running container '$CONTAINER_ID'"
echo "    config: $CONTAINER_CONFIG"
echo "    bundle: $BUNDLE_PATH"

# If overlay is configured, mount it before running crun
IS_READONLY=$(jq -r 'if .readonly == false then "false" else "true" end' "$CONTAINER_META")
if [[ "$IS_READONLY" != "true" ]]; then
    LOWER=$(jq -r '.overlay.lower' "$CONTAINER_META")
    UPPER=$(jq -r '.overlay.upper' "$CONTAINER_META")
    WORK=$(jq -r '.overlay.work' "$CONTAINER_META")
    MERGED=$(jq -r '.overlay.merged' "$CONTAINER_META")

    if mountpoint -q "$MERGED" 2>/dev/null; then
        echo "    overlay: already mounted"
    else
        echo "    overlay: mounting (lower=$LOWER)"
        sudo mount -t overlay overlay \
            -o "lowerdir=$LOWER,upperdir=$UPPER,workdir=$WORK" \
            "$MERGED"
    fi

    # Unmount overlay after crun exits (whether success or failure)
    cleanup_overlay() {
        sudo umount "$MERGED" 2>/dev/null || true
    }
    trap cleanup_overlay EXIT
fi

sudo crun run --bundle "$BUNDLE_PATH" --config "$CONTAINER_CONFIG" "$CONTAINER_ID"
