#!/bin/bash
set -euo pipefail

# add-nat-network.sh <container-id>
# Connects an existing container to the tcr NAT network.
#
# Must be called after create-container.sh and before run-container.sh.
# Requires the NAT network to exist (run create-nat-network.sh first).
# Requires root privileges.
#
# What it does:
#   1. Allocates an IP address from the NAT subnet
#   2. Creates a named network namespace (tcr-<container-id>)
#   3. Creates a veth pair: host end attached to bridge, container end as eth0
#   4. Configures IP address, default route, and loopback in the namespace
#   5. Generates resolv.conf with host's nameservers and bind-mounts it
#   6. Patches config.json to use the pre-configured network namespace
#   7. Updates container and network metadata with allocation info
#
# This uses pre-configured network namespaces rather than OCI hooks:
#   - crun creates a new (empty) network namespace by default
#   - We create a named netns, configure it fully, then point config.json to it
#   - crun joins the existing namespace instead of creating a new one
#
# Examples:
#   sudo ./add-nat-network.sh mycontainer
#   sudo ./add-nat-network.sh alpine_latest-a1b2c3d4

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GLOBAL_DIR="$SCRIPT_DIR/data/global"
NETWORK_META="$GLOBAL_DIR/tcr-network.json"
CONTAINERS_DIR="$SCRIPT_DIR/data/containers"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <container-id>"
    echo ""
    echo "Connects a container to the tcr NAT network."
    echo "Run create-nat-network.sh first to create the network."
    exit 1
fi

CONTAINER_ID="$1"
CONTAINER_DIR="$CONTAINERS_DIR/$CONTAINER_ID"
CONTAINER_CONFIG="$CONTAINER_DIR/config.json"
CONTAINER_META="$CONTAINER_DIR/tcr-container.json"

# ── Validate prerequisites ──
if [[ ! -f "$NETWORK_META" ]]; then
    echo "Error: NAT network not found. Run create-nat-network.sh first."
    exit 1
fi

if [[ ! -f "$CONTAINER_CONFIG" ]]; then
    echo "Error: Container '$CONTAINER_ID' not found"
    echo "Run create-container.sh first."
    exit 1
fi

if [[ ! -f "$CONTAINER_META" ]]; then
    echo "Error: Container metadata not found at $CONTAINER_META"
    exit 1
fi

# Check if this container already has a network configured
if jq -e '.network' "$CONTAINER_META" &>/dev/null; then
    echo "Error: Container '$CONTAINER_ID' already has a network configured"
    echo "IP: $(jq -r '.network.ip' "$CONTAINER_META")"
    exit 1
fi

# Read network configuration
BRIDGE=$(jq -r '.bridge' "$NETWORK_META")
GATEWAY=$(jq -r '.gateway' "$NETWORK_META")
SUBNET=$(jq -r '.subnet' "$NETWORK_META")
SUBNET_BASE=$(jq -r '.subnetBase' "$NETWORK_META")

# Check bridge exists
if ! ip link show "$BRIDGE" &>/dev/null; then
    echo "Error: Bridge '$BRIDGE' does not exist"
    echo "Recreate with: sudo ./create-nat-network.sh"
    exit 1
fi

# ── Allocate IP ──
echo "==> Allocating IP address..."

# Get all currently allocated IPs
ALLOCATED_IPS=$(jq -r '.allocations | values[]' "$NETWORK_META")

# Find first available IP in .2-.254
CONTAINER_IP=""
for i in $(seq 2 254); do
    CANDIDATE="${SUBNET_BASE}.${i}"
    if ! echo "$ALLOCATED_IPS" | grep -qxF "$CANDIDATE"; then
        CONTAINER_IP="$CANDIDATE"
        break
    fi
done

if [[ -z "$CONTAINER_IP" ]]; then
    echo "Error: No available IPs in subnet $SUBNET"
    exit 1
fi

echo "    allocated: $CONTAINER_IP/24"

# ── Naming ──
NETNS_NAME="tcr-${CONTAINER_ID}"
NETNS_PATH="/var/run/netns/$NETNS_NAME"

# Veth interface names (max 15 chars)
# Use first 7 hex chars of md5 hash for uniqueness
VETH_HASH=$(echo -n "$CONTAINER_ID" | md5sum | head -c 7)
VETH_HOST="veth${VETH_HASH}"
VETH_TEMP="vtmp${VETH_HASH}"

echo "==> Setting up network for container '$CONTAINER_ID'"
echo "    netns:   $NETNS_NAME"
echo "    veth:    $VETH_HOST (host) <-> eth0 (container)"
echo "    ip:      $CONTAINER_IP/24"
echo "    gateway: $GATEWAY"
echo "    bridge:  $BRIDGE"

# ── Rollback on failure ──
NETNS_CREATED=false
VETH_CREATED=false

cleanup_on_error() {
    echo "==> Error occurred, rolling back network setup..."
    if [[ "$VETH_CREATED" == true ]]; then
        ip link del "$VETH_HOST" 2>/dev/null || true
    fi
    if [[ "$NETNS_CREATED" == true ]]; then
        ip netns del "$NETNS_NAME" 2>/dev/null || true
    fi
    exit 1
}
trap cleanup_on_error ERR

# ── Create named network namespace ──
ip netns add "$NETNS_NAME"
NETNS_CREATED=true

# ── Create veth pair ──
ip link add "$VETH_HOST" type veth peer name "$VETH_TEMP"
VETH_CREATED=true

# Attach host end to bridge and bring up
ip link set "$VETH_HOST" master "$BRIDGE"
ip link set "$VETH_HOST" up

# Move container end into the namespace
ip link set "$VETH_TEMP" netns "$NETNS_NAME"
VETH_CREATED=false  # now managed by netns (deleted when netns is deleted)

# ── Configure inside the namespace ──
# Rename temp interface to eth0
ip netns exec "$NETNS_NAME" ip link set "$VETH_TEMP" name eth0

# Assign IP address
ip netns exec "$NETNS_NAME" ip addr add "${CONTAINER_IP}/24" dev eth0

# Bring up eth0 and loopback
ip netns exec "$NETNS_NAME" ip link set eth0 up
ip netns exec "$NETNS_NAME" ip link set lo up

# Set default route via the bridge gateway
ip netns exec "$NETNS_NAME" ip route add default via "$GATEWAY"

# ── Generate resolv.conf ──
RESOLV_FILE="$CONTAINER_DIR/resolv.conf"
{
    echo "# Generated by add-nat-network.sh for container $CONTAINER_ID"
    # On systemd-resolved systems, /etc/resolv.conf points to the stub resolver
    # (127.0.0.53) which is unreachable from container netns. Use resolvectl to
    # get the actual upstream DNS servers instead.
    if command -v resolvectl &>/dev/null; then
        # Extract DNS server lines from resolvectl (e.g., "DNS Servers: 192.168.64.1")
        resolvectl status 2>/dev/null \
            | grep -oP '(?<=DNS Servers: ).*' \
            | tr ' ' '\n' \
            | grep -v '^$' \
            | grep -v ':' \
            | while read -r ns; do echo "nameserver $ns"; done
    fi

    # If resolvectl produced nothing, fall back to /etc/resolv.conf (skip 127.0.0.53)
    if [[ ! -s "$RESOLV_FILE" ]] || ! grep -q '^nameserver' "$RESOLV_FILE" 2>/dev/null; then
        grep '^nameserver' /etc/resolv.conf 2>/dev/null | grep -v '127.0.0.53' || true
    fi
} > "$RESOLV_FILE"

# If still empty, use public DNS as last resort
if ! grep -q '^nameserver' "$RESOLV_FILE"; then
    echo "nameserver 8.8.8.8" >> "$RESOLV_FILE"
    echo "nameserver 8.8.4.4" >> "$RESOLV_FILE"
fi

echo "==> DNS: $RESOLV_FILE"

# ── Patch container config.json ──
echo "==> Patching config.json..."

# 1. Update network namespace to use the pre-configured named netns
# 2. Add bind mount for resolv.conf
jq --arg nspath "$NETNS_PATH" \
   --arg resolv "$(realpath "$RESOLV_FILE")" \
   '
   # Replace the network namespace entry with a path to our pre-configured netns
   .linux.namespaces = [.linux.namespaces[] |
       if .type == "network" then {type: "network", path: $nspath} else . end
   ]
   # Bind-mount our resolv.conf into the container
   | .mounts += [{
       "destination": "/etc/resolv.conf",
       "type": "bind",
       "source": $resolv,
       "options": ["bind", "ro"]
   }]
   ' "$CONTAINER_CONFIG" > "$CONTAINER_CONFIG.tmp" \
   && mv "$CONTAINER_CONFIG.tmp" "$CONTAINER_CONFIG"

# ── Update container metadata ──
jq --arg ip "$CONTAINER_IP" \
   --arg gateway "$GATEWAY" \
   --arg netns "$NETNS_NAME" \
   --arg veth "$VETH_HOST" \
   --arg bridge "$BRIDGE" \
   '. + {network: {ip: $ip, gateway: $gateway, netns: $netns, vethHost: $veth, bridge: $bridge}}' \
   "$CONTAINER_META" > "$CONTAINER_META.tmp" \
   && mv "$CONTAINER_META.tmp" "$CONTAINER_META"

# ── Update network allocations ──
jq --arg id "$CONTAINER_ID" --arg ip "$CONTAINER_IP" \
   '.allocations[$id] = $ip' \
   "$NETWORK_META" > "$NETWORK_META.tmp" \
   && mv "$NETWORK_META.tmp" "$NETWORK_META"

# ── Add /etc/hosts entry for host-local DNS resolution ──
HOSTNAME_ENTRY="tcr-${CONTAINER_ID}"
echo "==> Adding /etc/hosts entry: $CONTAINER_IP $HOSTNAME_ENTRY"
(
    flock -w 5 200 || { echo "Warning: Could not lock /etc/hosts, skipping"; exit 0; }
    # Remove any stale entry for this container first
    sed -i "/# tcr:${CONTAINER_ID}$/d" /etc/hosts
    echo "$CONTAINER_IP $HOSTNAME_ENTRY # tcr:${CONTAINER_ID}" >> /etc/hosts
) 200>/etc/hosts.tcr.lock

trap - ERR

echo "==> Network configured for container '$CONTAINER_ID'"
echo "    IP:      $CONTAINER_IP/24"
echo "    Gateway: $GATEWAY"
echo "    DNS:     $(grep 'nameserver' "$RESOLV_FILE" | head -1)"
echo "    Host:    $HOSTNAME_ENTRY -> $CONTAINER_IP"
echo ""
echo "To verify (from host): ip netns exec $NETNS_NAME ip addr"
echo "Host-local access:     curl http://$HOSTNAME_ENTRY:<port>/"
echo "To run:                ./run-container.sh $CONTAINER_ID"
