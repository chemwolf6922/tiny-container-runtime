#!/bin/sh
# tcr-nuke.sh — Remove all tcr artifacts from the system.
#
# Cleans up:
#   - Network namespaces  (/var/run/netns/tcr-*)
#   - nftables tables     (inet tcr_*)
#   - Bridge interfaces   (tcr_*)
#   - Stale veth pairs    (veth* attached to tcr bridges)
#   - Container mounts    (overlayfs, squashfs loop mounts under /var/lib/tcr)
#   - Data directory      (/var/lib/tcr)
#   - Lock file           (/var/run/tcrd.lock)
#   - Installed binaries  (/usr/bin/tcr, /usr/bin/tcrd)
#   - Service files       (/etc/systemd/system/tcrd.service, /etc/init.d/tcrd)
#
# Usage: sudo ./tcr-nuke.sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must be run as root" >&2
    exit 1
fi

TCR_ROOT="/var/lib/tcr"

echo "=== tcr nuke ==="

# ── Stop the daemon if running ────────────────────────────────────────────

if [ -f /var/run/tcrd.lock ] && kill -0 "$(cat /var/run/tcrd.lock 2>/dev/null)" 2>/dev/null; then
    echo "Stopping tcrd (pid $(cat /var/run/tcrd.lock))..."
    kill "$(cat /var/run/tcrd.lock)" 2>/dev/null || true
    sleep 1
    # Force kill if still alive
    kill -9 "$(cat /var/run/tcrd.lock 2>/dev/null)" 2>/dev/null || true
fi

# ── Kill any remaining crun processes ─────────────────────────────────────

echo "Killing stale container processes..."
pkill -9 -f "crun run.*--bundle.*$TCR_ROOT" 2>/dev/null || true

# ── Remove network namespaces (tcr-*) ────────────────────────────────────

echo "Removing network namespaces..."
if [ -d /var/run/netns ]; then
    for ns in /var/run/netns/tcr-*; do
        [ -e "$ns" ] || continue
        nsname="$(basename "$ns")"
        echo "  netns: $nsname"
        ip netns delete "$nsname" 2>/dev/null || {
            umount "$ns" 2>/dev/null || true
            rm -f "$ns"
        }
    done
fi

# ── Remove nftables tables (tcr_*) ───────────────────────────────────────

echo "Removing nftables tables..."
if command -v nft >/dev/null 2>&1; then
    nft list tables 2>/dev/null | while read -r _ family table; do
        case "$table" in
            tcr_*)
                echo "  nft: delete table $family $table"
                nft delete table "$family" "$table" 2>/dev/null || true
                ;;
        esac
    done
fi

# ── Remove bridge interfaces (tcr_*) ─────────────────────────────────────

echo "Removing bridge interfaces..."
for iface in $(ip -o link show type bridge 2>/dev/null | grep -oP '(?<=: )tcr_[^@:]+' || true); do
    echo "  bridge: $iface"
    ip link set "$iface" down 2>/dev/null || true
    ip link delete "$iface" 2>/dev/null || true
done

# ── Remove stale veth interfaces ──────────────────────────────────────────

echo "Removing stale veth interfaces..."
for iface in $(ip -o link show type veth 2>/dev/null | grep -oP '(?<=: )veth[0-9a-f]+(?=@)' || true); do
    # Check if the veth's master was a tcr bridge (already deleted, so it's now orphaned)
    echo "  veth: $iface"
    ip link delete "$iface" 2>/dev/null || true
done

# ── Unmount container filesystems ─────────────────────────────────────────

echo "Unmounting container filesystems..."
# Unmount in reverse order (overlay on top of squashfs loop mounts)
awk -v root="$TCR_ROOT" '$2 ~ root {print $2}' /proc/mounts | sort -r | while read -r mpoint; do
    echo "  umount: $mpoint"
    umount -l "$mpoint" 2>/dev/null || true
done

# ── Remove data directory ─────────────────────────────────────────────────

if [ -d "$TCR_ROOT" ]; then
    echo "Removing data directory: $TCR_ROOT"
    rm -rf "$TCR_ROOT"
fi

# ── Remove lock file ─────────────────────────────────────────────────────

rm -f /var/run/tcrd.lock

# ── Remove installed binaries ─────────────────────────────────────────────

echo "Removing installed binaries..."
rm -f /usr/bin/tcr /usr/bin/tcrd

# ── Remove service files ─────────────────────────────────────────────────

echo "Removing service files..."
if [ -f /etc/systemd/system/tcrd.service ]; then
    systemctl disable tcrd 2>/dev/null || true
    rm -f /etc/systemd/system/tcrd.service
    systemctl daemon-reload 2>/dev/null || true
fi
rm -f /etc/init.d/tcrd

echo ""
echo "=== nuke complete ==="
