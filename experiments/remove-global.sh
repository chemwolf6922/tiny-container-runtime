#!/bin/bash
set -euo pipefail

# remove-global.sh
# Removes global tcr resources (NAT network bridge, iptables rules, metadata).
#
# This tears down everything created by create-nat-network.sh.
# All containers using the network should be removed first.
# Requires root privileges.
#
# Examples:
#   sudo ./remove-global.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GLOBAL_DIR="$SCRIPT_DIR/data/global"
NETWORK_META="$GLOBAL_DIR/tcr-network.json"
CONTAINERS_DIR="$SCRIPT_DIR/data/containers"

# ── Remove NAT network ──
if [[ -f "$NETWORK_META" ]]; then
    BRIDGE=$(jq -r '.bridge' "$NETWORK_META")
    SUBNET=$(jq -r '.subnet' "$NETWORK_META")

    # Warn if any containers still have network allocations
    ALLOC_COUNT=$(jq '.allocations | length' "$NETWORK_META")
    if [[ "$ALLOC_COUNT" -gt 0 ]]; then
        echo "Warning: $ALLOC_COUNT container(s) still have IP allocations:"
        jq -r '.allocations | to_entries[] | "  \(.key): \(.value)"' "$NETWORK_META"
        echo "Their network namespaces will be orphaned. Remove containers first."
        echo ""
    fi

    echo "==> Removing NAT network"
    echo "    bridge: $BRIDGE"
    echo "    subnet: $SUBNET"

    # Remove iptables rules
    echo "==> Removing iptables rules..."
    iptables -t nat -D POSTROUTING -s "$SUBNET" ! -o "$BRIDGE" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$BRIDGE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    # Delete bridge (also removes any attached veth host ends)
    if ip link show "$BRIDGE" &>/dev/null; then
        echo "==> Deleting bridge '$BRIDGE'..."
        ip link set "$BRIDGE" down
        ip link del "$BRIDGE"
    else
        echo "==> Bridge '$BRIDGE' not found (already removed?)"
    fi

    # Remove metadata
    echo "==> Removing $NETWORK_META"
    rm -f "$NETWORK_META"

    echo "==> NAT network removed"
else
    echo "==> No NAT network configured (no metadata at $NETWORK_META)"
fi

# Clean up global dir if empty
if [[ -d "$GLOBAL_DIR" ]] && [[ -z "$(ls -A "$GLOBAL_DIR")" ]]; then
    rmdir "$GLOBAL_DIR"
fi

echo "==> Done"
