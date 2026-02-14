#!/bin/bash
set -euo pipefail

# remove-container.sh <container-id>
# Removes a container instance created by create-container.sh.
#
# This cleans up:
#   - crun state (if the container is still registered / running)
#   - data/containers/<container-id>/ directory
#
# Examples:
#   sudo ./remove-container.sh test1
#   sudo ./remove-container.sh alpine_latest-a1b2c3d4

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

if [[ ! -d "$CONTAINER_DIR" ]]; then
    echo "Error: Container '$CONTAINER_ID' not found at $CONTAINER_DIR"
    exit 1
fi

# If crun still knows about this container, kill and delete it
if sudo crun list 2>/dev/null | grep -q "^$CONTAINER_ID "; then
    STATUS=$(sudo crun state "$CONTAINER_ID" 2>/dev/null | jq -r '.status // "unknown"')
    echo "==> Container '$CONTAINER_ID' is registered with crun (status: $STATUS)"
    if [[ "$STATUS" == "running" ]]; then
        echo "==> Killing container..."
        sudo crun kill "$CONTAINER_ID" SIGKILL 2>/dev/null || true
        sleep 1
    fi
    echo "==> Deleting container from crun..."
    sudo crun delete "$CONTAINER_ID" 2>/dev/null || true
fi

# Remove the container directory
echo "==> Removing $CONTAINER_DIR"
sudo rm -rf "$CONTAINER_DIR"

echo "==> Container '$CONTAINER_ID' removed"
