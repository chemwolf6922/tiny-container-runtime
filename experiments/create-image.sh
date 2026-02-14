#!/bin/bash
set -euo pipefail

# create-image.sh <image>
# Example: ./create-image.sh docker.io/library/alpine:latest
#
# Pulls an OCI image using skopeo, unpacks it with umoci into a flat rootfs,
# generates tcr-config.json metadata, and packages everything into a squashfs
# image file.
#
# Output: data/<sanitized-name>.sqfs
#
# This script is meant to run on a powerful build machine, not on the target device.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <image>"
    echo "Example: $0 docker.io/library/alpine:latest"
    exit 1
fi

IMAGE="$1"

# Sanitize image name for use as directory/file name
# docker.io/library/alpine:latest -> alpine_latest
SANITIZED_NAME=$(echo "$IMAGE" | sed 's|.*/||; s/:/_/g; s/[^a-zA-Z0-9_.-]/_/g')
TAG=$(echo "$IMAGE" | grep -oP '(?<=:)[^:]+$' || echo "latest")
# Extract registry and repository for metadata
REGISTRY=$(echo "$IMAGE" | grep -oP '^[^/]+' || echo "docker.io")
REPO=$(echo "$IMAGE" | sed 's|^[^/]*/||; s|:.*||')

WORK_DIR="$DATA_DIR/.build-$SANITIZED_NAME"
OCI_DIR="$WORK_DIR/oci-image"
STAGE_DIR="$WORK_DIR/stage"    # staging area for squashfs contents
BUNDLE_DIR="$STAGE_DIR/bundle"
SQFS_FILE="$DATA_DIR/$SANITIZED_NAME.sqfs"

echo "==> Image: $IMAGE"
echo "==> Name: $SANITIZED_NAME"
echo "==> Output: $SQFS_FILE"

# Clean up previous build artifacts
if [[ -d "$WORK_DIR" ]]; then
    echo "==> Cleaning previous build dir..."
    sudo rm -rf "$WORK_DIR"
fi
rm -f "$SQFS_FILE"

mkdir -p "$WORK_DIR" "$STAGE_DIR"

# ── Step 1: Pull image to OCI layout ──
echo "==> Pulling image to OCI layout..."
skopeo copy "docker://$IMAGE" "oci:$OCI_DIR:$TAG"

# Get image digest and arch for metadata
DIGEST=$(skopeo inspect "oci:$OCI_DIR:$TAG" | jq -r '.Digest // "unknown"')
ARCH=$(skopeo inspect "oci:$OCI_DIR:$TAG" | jq -r '.Architecture // "unknown"')

# ── Step 2: Unpack to bundle ──
echo "==> Unpacking OCI image to bundle..."
sudo umoci unpack --image "$OCI_DIR:$TAG" "$BUNDLE_DIR"

# ── Step 3: Generate tcr-config.json ──
echo "==> Generating tcr-config.json..."
cat > "$STAGE_DIR/tcr-config.json" <<EOF
{
    "version": "0.1.0",
    "image": {
        "registry": "$REGISTRY",
        "repository": "$REPO",
        "tag": "$TAG",
        "digest": "$DIGEST",
        "arch": "$ARCH"
    },
    "bundlePath": "bundle",
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "==> tcr-config.json:"
cat "$STAGE_DIR/tcr-config.json"

# ── Step 4: Package into squashfs ──
echo "==> Creating squashfs image..."
sudo mksquashfs "$STAGE_DIR" "$SQFS_FILE" -noappend -comp zstd -quiet

# Clean up build artifacts
echo "==> Cleaning up build artifacts..."
sudo rm -rf "$WORK_DIR"

echo ""
echo "==> Done! Image: $SQFS_FILE"
ls -lh "$SQFS_FILE"
echo ""
echo "To load on target: ./load-image.sh $SQFS_FILE"
