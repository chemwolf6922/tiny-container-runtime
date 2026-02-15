#!/bin/bash
set -euo pipefail

# add-tmp-mount.sh [options] <container-id> <container-path>
# Adds a tmpfs mount to an existing container's config.json.
#
# Must be called after create-container.sh and before run-container.sh.
# Can be called multiple times to add multiple tmpfs mounts.
#
# Options:
#   -s <size>   Size limit (default: 64m). Supports k, m, g suffixes.
#   -m <mode>   Permission mode (default: 1777)
#
# Examples:
#   sudo ./add-tmp-mount.sh mycontainer /tmp
#   sudo ./add-tmp-mount.sh -s 128m mycontainer /run
#   sudo ./add-tmp-mount.sh -s 16m -m 0755 mycontainer /var/cache

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINERS_DIR="$SCRIPT_DIR/data/containers"

SIZE="64m"
MODE="1777"

while getopts ":s:m:" opt; do
    case $opt in
        s) SIZE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        \?) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
        :)  echo "Option -$OPTARG requires an argument" >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 [-s size] [-m mode] <container-id> <container-path>"
    echo "  -s <size>   Size limit (default: 64m)"
    echo "  -m <mode>   Permission mode (default: 1777)"
    echo ""
    echo "Examples:"
    echo "  $0 mycontainer /tmp"
    echo "  $0 -s 128m mycontainer /run"
    echo "  $0 -s 16m -m 0755 mycontainer /var/cache"
    exit 1
fi

CONTAINER_ID="$1"
CONTAINER_PATH="$2"

CONTAINER_DIR="$CONTAINERS_DIR/$CONTAINER_ID"
CONTAINER_CONFIG="$CONTAINER_DIR/config.json"

if [[ ! -f "$CONTAINER_CONFIG" ]]; then
    echo "Error: Container '$CONTAINER_ID' not found"
    echo "Run create-container.sh first."
    exit 1
fi

# Ensure container path is absolute
if [[ "$CONTAINER_PATH" != /* ]]; then
    echo "Error: Container path must be absolute (start with /): $CONTAINER_PATH"
    exit 1
fi


echo "==> Adding tmpfs mount to container '$CONTAINER_ID'"
echo "    path: $CONTAINER_PATH"
echo "    size: $SIZE"
echo "    mode: $MODE"

# Patch config.json: append tmpfs mount to .mounts array
jq --arg dst "$CONTAINER_PATH" \
   --arg size "$SIZE" \
   --arg mode "$MODE" \
   '.mounts += [{"destination": $dst, "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=\($mode)", "size=\($size)"]}]' \
   "$CONTAINER_CONFIG" > "$CONTAINER_CONFIG.tmp" \
   && mv "$CONTAINER_CONFIG.tmp" "$CONTAINER_CONFIG"

echo "==> tmpfs mount added"
