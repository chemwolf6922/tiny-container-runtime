# Agent Context: tiny-container-runtime experiments

## Project Goal

Build a tiny container runtime for resource-limited embedded devices. The workflow is split:
- **Build machine** (normal PC): pull images, flatten, package into squashfs
- **Target device** (embedded): mount squashfs, configure container, run with crun

Currently in the **experimental phase** using shell scripts.

## Architecture & Design Decisions

### Tool chain

**Build machine** (create-image.sh):
- **skopeo**: Pull images from registries directly to OCI Image Layout (no Docker daemon needed)
- **umoci**: Unpack OCI Image Layout into an OCI runtime bundle (flattened rootfs + base config.json). Handles layer merging and whiteout files automatically.
- **mksquashfs** (squashfs-tools): Package the bundle + metadata into a compressed squashfs image
- **jq**: JSON manipulation

**Target device** (load-image.sh, create-container.sh, run-container.sh):
- **mount** (kernel squashfs): Mount squashfs image read-only (no extraction needed)
- **crun**: OCI-compliant low-level container runtime
- **jq**: JSON manipulation for patching config.json

### Script responsibilities

| Script | Runs on | Purpose |
|--------|---------|---------|
| `create-image.sh <image>` | Build PC | skopeo pull → umoci unpack → generate tcr-config.json → mksquashfs → outputs `data/<name>.sqfs` |
| `load-image.sh <sqfs-file>` | Target | Mount squashfs image to `data/images/<name>/` (read-only) |
| `create-container.sh [opts] <image-name> [-- cmd...]` | Target | Read skeleton config from mounted image → patch with security settings → write to `data/containers/<id>/config.json` |
| `add-bind-mount.sh [-r] <container-id> <host-path> <container-path>` | Target | Append a bind mount to container's config.json. `-r` for read-only. |
| `add-tmp-mount.sh [-s size] [-m mode] <container-id> <container-path>` | Target | Append a tmpfs mount to container's config.json. Default 64m, mode 1777. |
| `create-nat-network.sh [-s subnet] [-b bridge]` | Target | Create global NAT network: bridge + nftables masquerade. One-time setup. |
| `add-nat-network.sh <container-id>` | Target | Connect container to NAT network: allocate IP, create veth pair, patch config.json |
| `run-container.sh <container-id>` | Target | `sudo crun run --bundle <image-bundle> --config <container-config> <id>` |
| `remove-container.sh <container-id>` | Target | Kill/delete crun state + clean up network + remove `data/containers/<id>/` |
| `remove-image.sh [-d] <image-name>` | Target | Unmount squashfs + remove mount dir. `-d` also deletes .sqfs file |
| `remove-global.sh` | Target | Remove global resources: tear down NAT bridge, nftables rules, delete `data/global/` |

### Security configuration

**Seccomp profile** (`seccomp.json`):
- Source: [containers/common](https://github.com/containers/common) `pkg/seccomp/seccomp.json`
- This is in the containers/common format (not raw OCI). `create-container.sh` converts it at patch time:
  - Strips `archMap` → only keeps architectures for the current platform (e.g., x86_64 → `SCMP_ARCH_X86_64`, `SCMP_ARCH_X86`, `SCMP_ARCH_X32`)
  - Strips `includes`, `excludes`, `comment`, `errno` fields from each syscall entry
  - Maps to OCI `linux.seccomp` schema: `{defaultAction, defaultErrnoRet, architectures, syscalls}`
- **Critical lesson**: Including all architectures (MIPS, ARM, etc.) causes `crun` to fail with "Numerical argument out of domain". Must filter to native arch only.

**Capabilities** (matches Docker/Podman defaults):
```
CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FSETID, CAP_FOWNER, CAP_MKNOD,
CAP_NET_RAW, CAP_SETGID, CAP_SETUID, CAP_SETFCAP, CAP_SETPCAP,
CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT, CAP_KILL, CAP_AUDIT_WRITE
```
Set on all 5 capability sets: bounding, effective, inheritable, permitted, ambient.

**Namespaces**: pid, ipc, uts, mount, network. By default, crun creates a new (empty) network namespace (loopback only). Use `add-nat-network.sh` to pre-configure a named netns with full NAT connectivity before running the container.

**Rootfs**: Default is read-write via overlayfs (image rootfs as lower layer, per-container upper layer for writes). Use `-r` flag in `create-container.sh` for read-only mode (direct image rootfs, no overlay).

### Networking (NAT)

**Architecture**: Pre-configured named network namespaces.

Instead of using OCI hooks or CNI plugins, networking is set up *before* `crun run`:
1. `create-nat-network.sh` creates a Linux bridge (`tcr0`) with nftables masquerade — run once.
2. `add-nat-network.sh` (per container) creates a named netns (`tcr-<container-id>`), a veth pair, assigns an IP, and patches `config.json` to point to the pre-existing netns via `linux.namespaces[].path`.
3. `crun run` joins the pre-configured namespace instead of creating a new empty one.

**Bridge setup** (`create-nat-network.sh`):
- Default bridge: `tcr0`, subnet `10.88.0.0/24`, gateway `10.88.0.1`
- Enables `net.ipv4.ip_forward=1`
- nftables: dedicated `table inet tcr` with NAT masquerade chain + forwarding chain
- Metadata stored in `data/global/tcr-network.json`

**Per-container setup** (`add-nat-network.sh`):
- IP allocation: scans `tcr-network.json` allocations, picks lowest unused `.2`–`.254`
- Creates named netns: `ip netns add tcr-<container-id>`
- Creates veth pair: `veth<hash>` (host, attached to bridge) ↔ `eth0` (in netns)
- Configures in netns: IP address, loopback up, default route via gateway
- Generates `resolv.conf` from host's nameservers, bind-mounts into container
- Patches `config.json`: `{"type": "network", "path": "/var/run/netns/tcr-<id>"}`
- Updates `tcr-container.json` with network info (ip, gateway, netns, vethHost)

**Cleanup** (`remove-container.sh`):
- Deletes named netns (auto-destroys container-side veth)
- Deletes host-side veth (if still present)
- Removes IP allocation from `tcr-network.json`

**DNS**: `add-nat-network.sh` copies the host's `/etc/resolv.conf` nameserver entries into a per-container `resolv.conf` file and bind-mounts it read-only at `/etc/resolv.conf` inside the container.

**Key design decision**: Named netns approach was chosen over OCI hooks because:
- No external hook binaries needed (simpler for embedded devices)
- Network can be verified from the host before container starts (`ip netns exec tcr-<id> ip addr`)
- Cleanup is straightforward (`ip netns del` + remove allocation)

### Key constraints & gotchas

1. **`umoci unpack` needs root** — it preserves file ownership (uid/gid) in rootfs, which requires `lchown` privileges.
2. **`crun run` needs root** — creating namespaces (especially PID, network) requires CAP_SYS_ADMIN. We run with `sudo`.
3. **`process.terminal`** — if set to `true`, crun expects a real TTY. Piping stdin or running non-interactively will fail with "tcgetattr: Inappropriate ioctl for device". Default is `false`; use `-t` flag in `create-container.sh` for interactive shells.
4. **crun has no command-line override for the container entrypoint** — the command must be baked into `config.json` before `crun run`. That's why command override is in `create-container.sh`, not `run-container.sh`. crun does support `--config` flag to use a config.json from a separate path than the bundle.
5. **Container IDs must be unique** — `crun run` will fail if a container with the same ID already exists (from a previous unclean exit). Use `sudo crun delete <id>` to clean up.
6. **squashfs as container image format** — squashfs is read-only, highly compressed, supports random access (no full extraction needed). It works as overlayfs lowerdir (proven by snap, OpenWrt, etc.). This is the chosen image distribution format.
7. **squashfs mount requires loop devices** — kernel must have `loop` and `squashfs` modules.

### Data layout
```
experiments/
  seccomp.json              # containers/common seccomp profile (source format)
  create-image.sh           # [build PC] pull + unpack + package
  load-image.sh             # [target] mount squashfs
  create-container.sh       # [target] patch config, set up overlay dirs
  add-bind-mount.sh         # [target] add bind mount to container config
  add-tmp-mount.sh          # [target] add tmpfs mount to container config
  create-nat-network.sh     # [target] create bridge + NAT (one-time)
  add-nat-network.sh        # [target] connect container to NAT network
  run-container.sh          # [target] mount overlay (if rw) + crun run
  remove-container.sh       # [target] kill + unmount overlay + rm network + rm container dir
  remove-image.sh           # [target] unmount squashfs + rm mount dir
  remove-global.sh          # [target] tear down NAT bridge + nftables + rm data/global/
  agent.md                  # this file
  data/
    global/
      tcr-network.json      # NAT network metadata (bridge, subnet, IP allocations)
    <name>.sqfs             # squashfs image files (output of create-image.sh)
    images/
      <name>/               # squashfs mount point (from load-image.sh, read-only)
        bundle/
          rootfs/            # flat filesystem
          config.json        # skeleton config (umoci output, unpatched)
        tcr-config.json      # image metadata (registry, tag, digest, arch, etc.)
    containers/
      <container-id>/        # per-instance writable directory
        config.json          # patched config (security, command, tty, rootfs path)
        tcr-container.json   # container metadata (id, image, overlay paths, readonly flag, network)
        resolv.conf          # (NAT network only) generated DNS config, bind-mounted
        overlay/             # (read-write mode only)
          upper/             # overlayfs upper layer (container writes land here)
          work/              # overlayfs work dir (required by kernel)
          merged/            # overlayfs merged mount point (used as container rootfs)
```

### tcr-config.json format
```json
{
    "version": "0.1.0",
    "image": {
        "registry": "docker.io",
        "repository": "library/alpine",
        "tag": "latest",
        "digest": "sha256:...",
        "arch": "amd64"
    },
    "bundlePath": "bundle",
    "created": "2026-02-14T..."
}
```

### Typical workflow
```bash
# === On build machine ===
# 1. Pull, unpack, and package into squashfs
./create-image.sh docker.io/library/alpine:latest
# Output: data/alpine_latest.sqfs

# === On target device ===
# 2. Mount the image
sudo ./load-image.sh data/alpine_latest.sqfs

# 3. Create a container instance (default: read-write with overlay)
sudo ./create-container.sh alpine_latest

# 3b. Read-only rootfs (no overlay)
sudo ./create-container.sh -r alpine_latest

# 3c. With TTY and command override
sudo ./create-container.sh -t -n myshell alpine_latest -- /bin/sh

# 3d. Add a bind mount (optional, before run)
sudo ./add-bind-mount.sh <container-id> /host/path /container/path

# 3e. Add a tmpfs mount (optional, before run)
sudo ./add-tmp-mount.sh <container-id> /tmp
sudo ./add-tmp-mount.sh -s 16m -m 0755 <container-id> /var/cache

# 3f. Connect to NAT network (optional, before run)
sudo ./create-nat-network.sh   # one-time setup
sudo ./add-nat-network.sh <container-id>

# 4. Run
./run-container.sh <container-id>

# === Cleanup ===
# 5. Remove container
sudo ./remove-container.sh <container-id>

# 6. Remove image (unmount only, keep .sqfs)
sudo ./remove-image.sh alpine_latest

# 6b. Remove image and delete .sqfs file
sudo ./remove-image.sh -d alpine_latest

# 7. Remove global resources (NAT network)
sudo ./remove-global.sh
```

### Testing status
- **create-image.sh**: TESTED — successfully pulls, unpacks, and creates .sqfs (alpine = 3.7MB on arm64)
- **load-image.sh**: TESTED — squashfs mount works in VM (Ubuntu 24.04, kernel 6.8.0-90-generic, aarch64). Loop device + squashfs built into kernel.
- **create-container.sh**: TESTED (full new flow) — reads skeleton config from squashfs mount, patches seccomp/caps/namespaces, writes to container dir. Both `-r` (read-only) and default (read-write overlay) modes work.
- **add-bind-mount.sh**: TESTED — directory bind mount (`/mnt`) and file bind mount (`/etc/hostname`) both work. Works with both read-only and overlay (read-write) rootfs.
- **add-tmp-mount.sh**: TESTED — tmpfs mount on `/tmp` (16m) works with read-only rootfs. Container can write to tmpfs, `df` shows correct size.
- **run-container.sh**: TESTED (full new flow) — mounts overlayfs before `crun run` (read-write mode), unmounts on exit. PID namespace isolated (PID 1). Read-only mode: `touch` fails with EROFS. Read-write mode: `touch` succeeds, written file appears in overlay upper layer.
- **create-nat-network.sh**: TESTED — creates bridge `tcr0` with gateway 10.88.0.1/24, nftables `inet tcr` table with masquerade, metadata written to `data/global/tcr-network.json`.
- **add-nat-network.sh**: TESTED — allocates IP (10.88.0.2), creates named netns + veth pair, patches config.json. Container successfully pings `bing.com` via NAT. DNS resolution works.
- **remove-container.sh**: network cleanup verified — deletes netns, veth, removes IP allocation from network metadata.

### Bug fixes during VM testing
- **run-container.sh**: `umoci unpack` creates `bundle/` with mode `0700` (root only). The `-d "$BUNDLE_PATH/rootfs"` check failed when run as non-root user (before the `sudo crun` exec). Fixed by changing to `sudo test -d` for the pre-flight check.
- **run-container.sh**: jq `//` (alternative operator) treats `false` as falsy, so `.readonly // true` returned `true` even when `readonly` was `false`. Fixed by using explicit `if .readonly == false then "false" else "true" end`.
- **add-nat-network.sh**: On systems with systemd-resolved, `/etc/resolv.conf` contains stub resolver `127.0.0.53` which is unreachable from container netns. Fixed by using `resolvectl status` to extract actual upstream DNS servers, falling back to non-stub entries in `/etc/resolv.conf`, then public DNS (8.8.8.8) as last resort.

### What's NOT implemented yet
- **Networking (NAT)**: Basic NAT networking works (`create-nat-network.sh` + `add-nat-network.sh`). No port mapping / port forwarding from host to container yet.
- **User namespace / rootless**: Everything runs as root. No rootless container support.
- **Container list command**: No `list-containers.sh` to show all containers and their status.
- **Persistent mounts**: squashfs loop mounts do NOT survive reboot. Must re-run `load-image.sh` after reboot (or add fstab entries).

### Required packages
**Build machine**: `skopeo`, `umoci`, `jq`, `squashfs-tools` (for mksquashfs)
**Target device**: `crun`, `jq`, `iproute2` (for `ip` commands), `nftables`, kernel with `squashfs` + `loop` + `overlayfs` + `veth` + `bridge` + `nf_tables` modules

