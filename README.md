# TCR — Tiny Container Runtime

> **Warning**: This project is almost entirely AI-generated and has **not** been human-reviewed line by line. Use it at your own risk, especially when running as root (which it requires). A thorough human review will be done when time permits. Contributions, testing, and code review are very welcome.

TCR is a minimal container runtime designed for resource-limited embedded devices. It uses [crun](https://github.com/containers/crun) as the low-level OCI runtime and [squashfs](https://docs.kernel.org/filesystems/squashfs.html) as the image format.

## Architecture

```
┌──────────┐         ┌──────────┐
│  tcr     │──RPC───▶│  tcrd    │
│ (client) │         │ (daemon) │
└──────────┘         └──────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
         containers    images     networks
          (crun)      (squashfs)  (nftables)
```

- **tcr** — thin CLI client, no business logic, forwards commands over a Unix domain socket
- **tcrd** — the daemon, manages containers, images, and networks

## Dependencies

Build:
- C compiler (gcc or clang)
- CMake ≥ 3.10
- libtev (event loop), libcjson, libuuid
- libnl-3, libnl-route-3
- libnftables

Runtime:
- Linux kernel with: overlayfs, squashfs, loop devices, network namespaces, nftables
- [crun](https://github.com/containers/crun)

Image creation (build machine only):
- skopeo, umoci, mksquashfs (squashfs-tools with zstd support)

## Building

```bash
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

This produces two binaries: `tcr` (client) and `tcrd` (daemon).

## Installation

```bash
# Install binaries to /usr/bin
sudo make install

# Install and enable the service (systemd or busybox init, auto-detected)
sudo make install-service
```

Override init system detection: `cmake .. -DINIT_SYSTEM=busybox`

### Uninstall

```bash
# Remove binaries and service files, keep data
sudo make uninstall

# Remove everything: binaries, service, data, network artifacts
sudo make nuke
```

## Quick Start

### 1. Create an image (on the build machine)

```bash
./host_tools/tcr-create-image.sh docker.io/library/alpine:latest alpine_latest.sqfs
```

This pulls the image, flattens it, and packages it into a squashfs file.

### 2. Start the daemon (on the target device)

```bash
sudo tcrd
```

Or via the service:

```bash
sudo systemctl start tcrd    # systemd
sudo /etc/init.d/tcrd start  # busybox init
```

### 3. Load the image

```bash
sudo tcr image load ./alpine_latest.sqfs
# sha256:1529d13528ed05668b2038ffab807ac8633ad6adfe6be8901adda62411f70d29
```

### 4. Run a container

```bash
# Interactive shell
sudo tcr run alpine /bin/sh

# Detached container with port forwarding
sudo tcr run -d --name web -p 8080:80 nginx

# Read-only, no network
sudo tcr run --no-network --read-only alpine cat /etc/os-release
```

## Command Reference

### Container Commands

```bash
tcr run [options] <image> [command...]    # Create and run a container
tcr ps                                    # List containers
tcr stop <name_or_id>                     # Graceful stop (SIGTERM → SIGKILL)
tcr kill <name_or_id>                     # Immediate stop (SIGKILL)
tcr rm <name_or_id>                       # Remove a container
```

### `tcr run` Options

| Flag | Description |
|---|---|
| `-d` | Run in detached mode (background) |
| `--name <name>` | Assign a name to the container |
| `--rm` | Auto-remove on exit |
| `--read-only` | Read-only rootfs (no overlay) |
| `-t` | Allocate a pseudo-TTY |
| `-e KEY=VALUE` | Set environment variable (repeatable) |
| `-v src:dst[:ro]` | Bind mount (repeatable) |
| `--tmpfs dst[:size]` | tmpfs mount (repeatable) |
| `-p hostPort:containerPort[/tcp\|udp]` | Port forwarding (repeatable) |
| `--network <name>` | Join a named NAT network (default: `tcr_default`) |
| `--no-network` | Disable networking |
| `--restart <policy>` | Restart policy: `no`, `unless-stopped`, `always` |
| `--stop-timeout <sec>` | Graceful stop timeout in seconds (default: 10) |

### Image Commands

```bash
tcr image load <path>     # Load a squashfs image
tcr image ls              # List loaded images
tcr image rm <ref>        # Remove an image (by digest or name:tag)
```

### Network Commands

```bash
tcr network ls            # List NAT networks
tcr network rm <name>     # Remove a NAT network
```

### Other

```bash
tcr help                  # Show usage
```

## Networking

Every container joins a NAT network by default (`tcr_default`), which provides:

- Internet access via nftables masquerade
- Inter-container DNS discovery (containers can reach each other by name)
- Port forwarding to the host (`-p`)

Use `--no-network` to disable, or `--network <name>` to use a named network.

## Data Layout

All daemon state lives under `/var/lib/tcr` (configurable with `tcrd --root <path>`):

```
/var/lib/tcr/
├── images_root/          # mounted squashfs images
├── networks/             # NAT network state
└── containers/           # container dirs (overlay, config, metadata)
```

## Running Tests

```bash
cd test/build && cmake .. && make -j$(nproc)

# Integration test (requires root, pulls alpine image on first run)
sudo ./run_test_tcrd.sh

# Unit tests (no root needed)
./test_rpc
./test_seccomp_resource
```

## Project Status

The core runtime is functional: image loading, container lifecycle, NAT networking, port forwarding, DNS discovery, and the daemon are all implemented and tested.

See [todo.md](todo.md) for planned features (`exec`, `logs`).
