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

# Unmount overlay if mounted
MERGED_DIR="$CONTAINER_DIR/overlay/merged"
if mountpoint -q "$MERGED_DIR" 2>/dev/null; then
    echo "==> Unmounting overlay at $MERGED_DIR"
    sudo umount "$MERGED_DIR"
fi

# Clean up network namespace and allocation (if container had NAT network)
CONTAINER_META="$CONTAINER_DIR/tcr-container.json"
NETWORK_META="$SCRIPT_DIR/data/global/tcr-network.json"

if [[ -f "$CONTAINER_META" ]] && jq -e '.network' "$CONTAINER_META" &>/dev/null; then
    NETNS_NAME=$(jq -r '.network.netns' "$CONTAINER_META")
    VETH_HOST=$(jq -r '.network.vethHost' "$CONTAINER_META")

    # Remove port forwarding nftables rules (tagged with comment "tcr-<container-id>")
    if nft list table inet tcr &>/dev/null; then
        COMMENT="tcr-${CONTAINER_ID}"
        for chain in prerouting forward; do
            if nft list chain inet tcr "$chain" &>/dev/null; then
                # Find rule handles matching our comment tag
                HANDLES=$(nft -a list chain inet tcr "$chain" 2>/dev/null \
                    | grep "comment \"$COMMENT\"" \
                    | grep -oP 'handle \K[0-9]+' || true)
                for handle in $HANDLES; do
                    nft delete rule inet tcr "$chain" handle "$handle"
                    echo "==> Removed port forwarding rule (chain=$chain, handle=$handle)"
                done
            fi
        done
    fi

    # Delete host-side veth (may already be gone if netns was deleted)
    if ip link show "$VETH_HOST" &>/dev/null; then
        echo "==> Deleting veth $VETH_HOST"
        ip link del "$VETH_HOST" 2>/dev/null || true
    fi

    # Delete the named network namespace (also removes container-side veth)
    if ip netns list | grep -qw "$NETNS_NAME"; then
        echo "==> Deleting network namespace $NETNS_NAME"
        ip netns del "$NETNS_NAME"
    fi

    # Remove IP allocation from network metadata
    if [[ -f "$NETWORK_META" ]]; then
        echo "==> Removing IP allocation"
        jq --arg id "$CONTAINER_ID" 'del(.allocations[$id])' \
            "$NETWORK_META" > "$NETWORK_META.tmp" \
            && mv "$NETWORK_META.tmp" "$NETWORK_META"
    fi

    # Remove /etc/hosts entry
    if grep -q "# tcr:${CONTAINER_ID}$" /etc/hosts 2>/dev/null; then
        echo "==> Removing /etc/hosts entry for tcr-${CONTAINER_ID}"
        (
            flock -w 5 200 || { echo "Warning: Could not lock /etc/hosts, skipping"; }
            sed -i "/# tcr:${CONTAINER_ID}$/d" /etc/hosts
        ) 200>/etc/hosts.tcr.lock
    fi
fi

# Remove the container directory
echo "==> Removing $CONTAINER_DIR"
sudo rm -rf "$CONTAINER_DIR"

echo "==> Container '$CONTAINER_ID' removed"
