#!/bin/bash
set -euo pipefail

# create-image.sh <image>
# Example: ./create-image.sh docker.io/library/alpine:latest
#
# Pulls an OCI image using skopeo and unpacks it into a flat rootfs
# using umoci. Output goes to data/<sanitized-name>/

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <image>"
    echo "Example: $0 docker.io/library/alpine:latest"
    exit 1
fi

IMAGE="$1"

# Sanitize image name for use as directory name
# docker.io/library/alpine:latest -> alpine_latest
SANITIZED_NAME=$(echo "$IMAGE" | sed 's|.*/||; s/:/_/g; s/[^a-zA-Z0-9_.-]/_/g')
TAG=$(echo "$IMAGE" | grep -oP '(?<=:)[^:]+$' || echo "latest")

IMAGE_DIR="$DATA_DIR/$SANITIZED_NAME"
OCI_DIR="$IMAGE_DIR/oci-image"
BUNDLE_DIR="$IMAGE_DIR/bundle"

echo "==> Image: $IMAGE"
echo "==> Name: $SANITIZED_NAME"
echo "==> Output: $IMAGE_DIR"

# Clean up previous data
if [[ -d "$IMAGE_DIR" ]]; then
    echo "==> Removing existing image dir: $IMAGE_DIR"
    rm -rf "$IMAGE_DIR"
fi

mkdir -p "$IMAGE_DIR"

# Step 1: Pull image to OCI layout using skopeo
echo "==> Pulling image to OCI layout..."
skopeo copy "docker://$IMAGE" "oci:$OCI_DIR:$TAG"

# Step 2: Unpack OCI image to a bundle (rootfs + config.json) using umoci
# Needs root to preserve file ownership in rootfs
echo "==> Unpacking OCI image to bundle..."
sudo umoci unpack --image "$OCI_DIR:$TAG" "$BUNDLE_DIR"

echo "==> Done! Bundle at: $BUNDLE_DIR"
echo "    rootfs: $BUNDLE_DIR/rootfs"
echo "    config: $BUNDLE_DIR/config.json"
ls -la "$BUNDLE_DIR"
