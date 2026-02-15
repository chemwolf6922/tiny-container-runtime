#!/bin/bash
set -euo pipefail

# create-nat-network.sh [options]
# Creates the global tcr NAT network with a Linux bridge and nftables masquerade.
#
# This must be run once before using add-nat-network.sh to connect containers.
# Requires root privileges.
#
# What it does:
#   1. Creates a Linux bridge interface (default: tcr0)
#   2. Assigns the gateway IP (.1 of the subnet) to the bridge
#   3. Enables IP forwarding (net.ipv4.ip_forward=1)
#   4. Adds nftables table "inet tcr" with NAT masquerade and forwarding rules
#   5. Saves network metadata to data/global/tcr-network.json
#
# Options:
#   -s <subnet>   Subnet in CIDR /24 notation (default: 10.88.0.0/24)
#   -b <bridge>   Bridge interface name (default: tcr0)
#
# Examples:
#   sudo ./create-nat-network.sh
#   sudo ./create-nat-network.sh -s 172.20.0.0/24
#   sudo ./create-nat-network.sh -b mybridge -s 10.99.0.0/24

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GLOBAL_DIR="$SCRIPT_DIR/data/global"
NETWORK_META="$GLOBAL_DIR/tcr-network.json"

BRIDGE="tcr0"
SUBNET="10.88.0.0/24"

while getopts ":s:b:" opt; do
    case $opt in
        s) SUBNET="$OPTARG" ;;
        b) BRIDGE="$OPTARG" ;;
        \?) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
        :)  echo "Option -$OPTARG requires an argument" >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

# Parse subnet — only /24 is supported
if [[ ! "$SUBNET" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.0/24$ ]]; then
    echo "Error: Only /24 subnets are supported (e.g., 10.88.0.0/24)"
    exit 1
fi
SUBNET_BASE="${BASH_REMATCH[1]}"
GATEWAY="${SUBNET_BASE}.1"

# Validate octets
IFS='.' read -r o1 o2 o3 <<< "$SUBNET_BASE"
for oct in "$o1" "$o2" "$o3"; do
    if [[ "$oct" -lt 0 || "$oct" -gt 255 ]]; then
        echo "Error: Invalid subnet: $SUBNET"
        exit 1
    fi
done

# Check if bridge already exists
if ip link show "$BRIDGE" &>/dev/null; then
    echo "Error: Bridge '$BRIDGE' already exists"
    echo "To recreate, first delete it: sudo ip link del $BRIDGE"
    exit 1
fi

# Check if network metadata already exists
if [[ -f "$NETWORK_META" ]]; then
    echo "Error: Network already configured. Metadata at: $NETWORK_META"
    echo "Remove it first if you want to recreate."
    exit 1
fi

echo "==> Creating NAT network"
echo "    bridge:  $BRIDGE"
echo "    subnet:  $SUBNET"
echo "    gateway: $GATEWAY"

# Rollback on failure
cleanup_on_error() {
    echo "==> Error occurred, rolling back..."
    ip link del "$BRIDGE" 2>/dev/null || true
    nft delete table inet tcr 2>/dev/null || true
    rm -f "$NETWORK_META"
    exit 1
}
trap cleanup_on_error ERR

# Ensure global dir exists
mkdir -p "$GLOBAL_DIR"

# ── 1. Create bridge interface ──
echo "==> Creating bridge interface '$BRIDGE'..."
ip link add name "$BRIDGE" type bridge
ip addr add "${GATEWAY}/24" dev "$BRIDGE"
ip link set "$BRIDGE" up

# ── 2. Enable IP forwarding ──
echo "==> Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# ── 3. Set up nftables NAT rules ──
# All rules live in a dedicated "inet tcr" table for easy cleanup.
echo "==> Configuring nftables NAT..."
nft add table inet tcr
nft add chain inet tcr postrouting '{ type nat hook postrouting priority 100 ; }'
nft add chain inet tcr forward '{ type filter hook forward priority 0 ; }'
# Masquerade traffic from containers going to the outside world
nft add rule inet tcr postrouting ip saddr "$SUBNET" oifname != "$BRIDGE" masquerade
# Allow forwarding from the bridge to external interfaces
nft add rule inet tcr forward iifname "$BRIDGE" accept
# Allow return traffic to containers
nft add rule inet tcr forward oifname "$BRIDGE" ct state related,established accept

# ── 4. Save network metadata ──
jq -n \
    --arg bridge "$BRIDGE" \
    --arg subnet "$SUBNET" \
    --arg gateway "$GATEWAY" \
    --arg base "$SUBNET_BASE" \
    --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        bridge: $bridge,
        subnet: $subnet,
        gateway: $gateway,
        subnetBase: $base,
        allocations: {},
        created: $created
    }' > "$NETWORK_META"

trap - ERR

echo "==> NAT network created successfully"
echo "    metadata: $NETWORK_META"
echo ""
echo "Containers can now use: ./add-nat-network.sh <container-id>"
