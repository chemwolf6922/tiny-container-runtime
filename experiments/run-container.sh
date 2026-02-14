#!/bin/bash
set -euo pipefail

# run-container.sh <image-name> [container-id]
# Runs a prepared container bundle with crun.
# Config (command, tty, etc.) is set by create-container.sh beforehand.
#
# Examples:
#   ./run-container.sh alpine_latest
#   ./run-container.sh alpine_latest my-alpine

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <image-name> [container-id]"
    exit 1
fi

IMAGE_NAME="$1"
CONTAINER_ID="${2:-$IMAGE_NAME-$$}"

BUNDLE_DIR="$DATA_DIR/$IMAGE_NAME/bundle"

if [[ ! -f "$BUNDLE_DIR/config.json" ]]; then
    echo "Error: No config.json in $BUNDLE_DIR"
    echo "Run create-image.sh and create-container.sh first."
    exit 1
fi

echo "==> Running container '$CONTAINER_ID' from bundle: $BUNDLE_DIR"
exec sudo crun run --bundle "$BUNDLE_DIR" "$CONTAINER_ID"
