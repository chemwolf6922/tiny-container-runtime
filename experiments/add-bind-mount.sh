#!/bin/bash
set -euo pipefail

# add-bind-mount.sh [options] <container-id> <host-path> <container-path>
# Adds a bind mount to an existing container's config.json.
#
# Must be called after create-container.sh and before run-container.sh.
# Can be called multiple times to add multiple bind mounts.
#
# Options:
#   -r    Read-only mount (default: read-write)
#
# Examples:
#   sudo ./add-bind-mount.sh mycontainer /host/data /mnt/data
#   sudo ./add-bind-mount.sh -r mycontainer /host/config /etc/app
#   sudo ./add-bind-mount.sh mycontainer /tmp/shared /tmp/shared

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINERS_DIR="$SCRIPT_DIR/data/containers"

READONLY=false

while getopts ":r" opt; do
    case $opt in
        r) READONLY=true ;;
        \?) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 [-r] <container-id> <host-path> <container-path>"
    echo "  -r    Read-only bind mount (default: read-write)"
    echo ""
    echo "Examples:"
    echo "  $0 mycontainer /host/data /mnt/data"
    echo "  $0 -r mycontainer /etc/hosts /etc/hosts"
    exit 1
fi

CONTAINER_ID="$1"
HOST_PATH="$2"
CONTAINER_PATH="$3"

CONTAINER_DIR="$CONTAINERS_DIR/$CONTAINER_ID"
CONTAINER_CONFIG="$CONTAINER_DIR/config.json"

if [[ ! -f "$CONTAINER_CONFIG" ]]; then
    echo "Error: Container '$CONTAINER_ID' not found"
    echo "Run create-container.sh first."
    exit 1
fi

# Resolve host path to absolute
HOST_PATH="$(realpath "$HOST_PATH")"

if [[ ! -e "$HOST_PATH" ]]; then
    echo "Error: Host path does not exist: $HOST_PATH"
    exit 1
fi

# Ensure container path is absolute
if [[ "$CONTAINER_PATH" != /* ]]; then
    echo "Error: Container path must be absolute (start with /): $CONTAINER_PATH"
    exit 1
fi


# Build mount options
OPTIONS='["bind"]'
if [[ "$READONLY" == true ]]; then
    OPTIONS='["bind", "ro"]'
fi

echo "==> Adding bind mount to container '$CONTAINER_ID'"
echo "    host:      $HOST_PATH"
echo "    container: $CONTAINER_PATH"
echo "    readonly:  $READONLY"

# Patch config.json: append bind mount to .mounts array
jq --arg src "$HOST_PATH" \
   --arg dst "$CONTAINER_PATH" \
   --argjson opts "$OPTIONS" \
   '.mounts += [{"destination": $dst, "type": "bind", "source": $src, "options": $opts}]' \
   "$CONTAINER_CONFIG" > "$CONTAINER_CONFIG.tmp" \
   && mv "$CONTAINER_CONFIG.tmp" "$CONTAINER_CONFIG"

echo "==> Bind mount added"
