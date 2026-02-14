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

if [[ ! -d "$BUNDLE_PATH/rootfs" ]]; then
    echo "Error: Image rootfs not found at $BUNDLE_PATH/rootfs"
    echo "Is the image still mounted? Check load-image.sh."
    exit 1
fi

echo "==> Running container '$CONTAINER_ID'"
echo "    config: $CONTAINER_CONFIG"
echo "    bundle: $BUNDLE_PATH"
exec sudo crun run --bundle "$BUNDLE_PATH" --config "$CONTAINER_CONFIG" "$CONTAINER_ID"
