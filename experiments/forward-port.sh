#!/bin/bash
set -euo pipefail

# forward-port.sh <container-id> [host-ip:]<host-port>:<container-port>[/<protocol>]
# Adds a port forwarding rule from the host to a container using nftables DNAT.
#
# Must be called after add-nat-network.sh and before run-container.sh.
# Can be called multiple times to add multiple forwarding rules.
# Requires root privileges.
#
# What it does:
#   1. Validates the container has a NAT network configured
#   2. Checks the host port is not already in use
#   3. Lazily creates the nftables prerouting chain (if not yet present)
#   4. Adds DNAT (prerouting) + forwarding rules with a comment tag for cleanup
#   5. Updates tcr-container.json with the port forwarding info
#
# This forwards external traffic arriving on the host to the container.
# For host-local access, use the container IP directly (from tcr-container.json).
#
# Port spec format:
#   <host-port>:<container-port>              -> binds 0.0.0.0, TCP
#   <host-port>:<container-port>/<protocol>   -> binds 0.0.0.0, specified protocol
#   <host-ip>:<host-port>:<container-port>    -> binds specified IP, TCP
#   <host-ip>:<host-port>:<container-port>/<protocol>
#
# Defaults:
#   host-ip:  0.0.0.0 (all interfaces)
#   protocol: tcp
#
# Examples:
#   sudo ./forward-port.sh mycontainer 8080:80
#   sudo ./forward-port.sh mycontainer 8080:80/tcp
#   sudo ./forward-port.sh mycontainer 5353:53/udp
#   sudo ./forward-port.sh mycontainer 192.168.1.10:443:443/tcp

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINERS_DIR="$SCRIPT_DIR/data/containers"
NETWORK_META="$SCRIPT_DIR/data/global/tcr-network.json"

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <container-id> [host-ip:]<host-port>:<container-port>[/<protocol>]"
    echo ""
    echo "Adds a port forwarding rule from the host to a container."
    echo "Forwards external traffic only. For local access, use the container IP directly."
    echo ""
    echo "Defaults: host-ip=0.0.0.0, protocol=tcp"
    echo ""
    echo "Examples:"
    echo "  $0 mycontainer 8080:80"
    echo "  $0 mycontainer 8080:80/tcp"
    echo "  $0 mycontainer 5353:53/udp"
    echo "  $0 mycontainer 192.168.1.10:443:443/tcp"
    exit 1
fi

CONTAINER_ID="$1"
PORT_SPEC="$2"
CONTAINER_DIR="$CONTAINERS_DIR/$CONTAINER_ID"
CONTAINER_META="$CONTAINER_DIR/tcr-container.json"

# ── Validate container ──
if [[ ! -f "$CONTAINER_META" ]]; then
    echo "Error: Container '$CONTAINER_ID' not found"
    echo "Run create-container.sh first."
    exit 1
fi

if ! jq -e '.network' "$CONTAINER_META" &>/dev/null; then
    echo "Error: Container '$CONTAINER_ID' has no NAT network configured"
    echo "Run add-nat-network.sh first."
    exit 1
fi

CONTAINER_IP=$(jq -r '.network.ip' "$CONTAINER_META")

# ── Parse port spec ──
# Split off protocol suffix first (default: tcp)
PROTOCOL="tcp"
if [[ "$PORT_SPEC" == */* ]]; then
    PROTOCOL="${PORT_SPEC##*/}"
    PORT_SPEC="${PORT_SPEC%/*}"
fi

# Validate protocol
PROTOCOL=$(echo "$PROTOCOL" | tr '[:upper:]' '[:lower:]')
if [[ "$PROTOCOL" != "tcp" && "$PROTOCOL" != "udp" ]]; then
    echo "Error: Unsupported protocol '$PROTOCOL'. Use tcp or udp."
    exit 1
fi

# Parse host-ip:host-port:container-port or host-port:container-port
HOST_IP="0.0.0.0"
IFS=':' read -ra PARTS <<< "$PORT_SPEC"

case ${#PARTS[@]} in
    2)
        HOST_PORT="${PARTS[0]}"
        CONTAINER_PORT="${PARTS[1]}"
        ;;
    3)
        HOST_IP="${PARTS[0]}"
        HOST_PORT="${PARTS[1]}"
        CONTAINER_PORT="${PARTS[2]}"
        ;;
    *)
        echo "Error: Invalid port spec format"
        echo "Expected: [host-ip:]<host-port>:<container-port>[/<protocol>]"
        exit 1
        ;;
esac

# Validate ports are numbers in range
validate_port() {
    local label="$1" port="$2"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        echo "Error: Invalid $label: $port (must be 1-65535)"
        exit 1
    fi
}
validate_port "host port" "$HOST_PORT"
validate_port "container port" "$CONTAINER_PORT"

# Validate host IP
if ! [[ "$HOST_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Invalid host IP: $HOST_IP"
    exit 1
fi

# Reject localhost bindings — DNAT only handles external (prerouting) traffic.
# For host-local access, use the container IP directly.
if [[ "$HOST_IP" == "127."* ]]; then
    echo "Error: Localhost binding is not supported for port forwarding"
    echo "For host-local access, use the container IP directly: $CONTAINER_IP"
    exit 1
fi

# ── Check host port availability ──
SS_PROTO="tcp"
[[ "$PROTOCOL" == "udp" ]] && SS_PROTO="udp"

if ss -lnH "sport = :${HOST_PORT}" 2>/dev/null | grep -q "$SS_PROTO"; then
    echo "Error: Host port $HOST_PORT/$PROTOCOL is already in use"
    ss -lnpH "sport = :${HOST_PORT}" 2>/dev/null | grep "$SS_PROTO" || true
    exit 1
fi

# ── Check for duplicate forwarding rule in container metadata ──
if jq -e --argjson hp "$HOST_PORT" --arg proto "$PROTOCOL" --arg hip "$HOST_IP" \
    '.portForwards // [] | any(.hostPort == $hp and .protocol == $proto and .hostIp == $hip)' \
    "$CONTAINER_META" 2>/dev/null | grep -q true; then
    echo "Error: Forwarding rule $HOST_IP:$HOST_PORT/$PROTOCOL already exists for this container"
    exit 1
fi

echo "==> Adding port forwarding for container '$CONTAINER_ID'"
echo "    $HOST_IP:$HOST_PORT -> $CONTAINER_IP:$CONTAINER_PORT/$PROTOCOL"

# ── Validate nftables table exists ──
if ! nft list table inet tcr &>/dev/null; then
    echo "Error: nftables table 'inet tcr' not found"
    echo "Run create-nat-network.sh first."
    exit 1
fi

# ── Lazily create prerouting chain ──
if ! nft list chain inet tcr prerouting &>/dev/null; then
    echo "==> Creating prerouting chain in 'inet tcr'..."
    nft add chain inet tcr prerouting '{ type nat hook prerouting priority -100 ; }'
fi

# ── Add nftables rules ──
COMMENT="tcr-${CONTAINER_ID}"

echo "==> Adding nftables DNAT rule..."
if [[ "$HOST_IP" == "0.0.0.0" ]]; then
    # Match any destination IP
    nft add rule inet tcr prerouting "$PROTOCOL" dport "$HOST_PORT" \
        dnat ip to "${CONTAINER_IP}:${CONTAINER_PORT}" \
        comment "\"$COMMENT\""
else
    # Match specific destination IP
    nft add rule inet tcr prerouting ip daddr "$HOST_IP" "$PROTOCOL" dport "$HOST_PORT" \
        dnat ip to "${CONTAINER_IP}:${CONTAINER_PORT}" \
        comment "\"$COMMENT\""
fi

echo "==> Adding nftables forward rule..."
nft add rule inet tcr forward ip daddr "$CONTAINER_IP" "$PROTOCOL" dport "$CONTAINER_PORT" \
    accept \
    comment "\"$COMMENT\""

# ── Update container metadata ──
echo "==> Updating container metadata..."
jq --argjson hp "$HOST_PORT" \
   --argjson cp "$CONTAINER_PORT" \
   --arg proto "$PROTOCOL" \
   --arg hip "$HOST_IP" \
   '.portForwards = (.portForwards // []) + [{hostIp: $hip, hostPort: $hp, containerPort: $cp, protocol: $proto}]' \
   "$CONTAINER_META" > "$CONTAINER_META.tmp" \
   && mv "$CONTAINER_META.tmp" "$CONTAINER_META"

echo "==> Port forwarding added: $HOST_IP:$HOST_PORT -> $CONTAINER_IP:$CONTAINER_PORT/$PROTOCOL"
echo ""
echo "Note: This forwards external traffic only."
echo "For host-local access, use: $CONTAINER_IP:$CONTAINER_PORT"
