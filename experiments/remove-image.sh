#!/bin/bash
set -euo pipefail

# remove-image.sh <image-name>
# Removes a loaded image: unmounts squashfs and optionally deletes the .sqfs file.
#
# This cleans up:
#   - squashfs mount at data/images/<image-name>/
#   - the mount point directory
#   - (with -d) the .sqfs file at data/<image-name>.sqfs
#
# Any containers using this image should be removed first.
#
# Options:
#   -d    Also delete the .sqfs file (default: keep it)
#
# Examples:
#   sudo ./remove-image.sh alpine_latest          # unmount only, keep .sqfs
#   sudo ./remove-image.sh -d alpine_latest       # unmount and delete .sqfs

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
IMAGES_DIR="$DATA_DIR/images"
CONTAINERS_DIR="$DATA_DIR/containers"

DELETE_SQFS=false

while getopts ":d" opt; do
    case $opt in
        d) DELETE_SQFS=true ;;
        \?) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 [-d] <image-name>"
    echo "  -d    Also delete the .sqfs file"
    echo ""
    echo "Loaded images:"
    if [[ -d "$IMAGES_DIR" ]]; then
        for d in "$IMAGES_DIR"/*/; do
            [[ -d "$d" ]] || continue
            name=$(basename "$d")
            if mountpoint -q "$d" 2>/dev/null; then
                echo "  $name (mounted)"
            else
                echo "  $name (not mounted)"
            fi
        done
    else
        echo "  (none)"
    fi
    exit 1
fi

IMAGE_NAME="$1"
MOUNT_DIR="$IMAGES_DIR/$IMAGE_NAME"
SQFS_FILE="$DATA_DIR/$IMAGE_NAME.sqfs"

if [[ ! -d "$MOUNT_DIR" ]]; then
    echo "Error: Image '$IMAGE_NAME' not found at $MOUNT_DIR"
    exit 1
fi

# Warn if any containers reference this image
if [[ -d "$CONTAINERS_DIR" ]]; then
    REFS=()
    for cdir in "$CONTAINERS_DIR"/*/; do
        [[ -f "$cdir/tcr-container.json" ]] || continue
        cimg=$(jq -r '.imageName // ""' "$cdir/tcr-container.json")
        if [[ "$cimg" == "$IMAGE_NAME" ]]; then
            REFS+=("$(basename "$cdir")")
        fi
    done
    if [[ ${#REFS[@]} -gt 0 ]]; then
        echo "Warning: The following containers use this image:"
        printf '  %s\n' "${REFS[@]}"
        echo "They should be removed first (remove-container.sh)."
        echo ""
    fi
fi

# Unmount if mounted
if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
    echo "==> Unmounting $MOUNT_DIR"
    sudo umount "$MOUNT_DIR"
else
    echo "==> Not mounted (skipping unmount)"
fi

# Remove mount point directory
echo "==> Removing $MOUNT_DIR"
rm -rf "$MOUNT_DIR"

# Optionally delete the .sqfs file
if [[ "$DELETE_SQFS" == true ]]; then
    if [[ -f "$SQFS_FILE" ]]; then
        echo "==> Deleting $SQFS_FILE"
        rm -f "$SQFS_FILE"
    else
        echo "==> No .sqfs file at $SQFS_FILE (skipping)"
    fi
else
    if [[ -f "$SQFS_FILE" ]]; then
        echo "==> Keeping $SQFS_FILE (use -d to delete)"
    fi
fi

echo "==> Image '$IMAGE_NAME' removed"
