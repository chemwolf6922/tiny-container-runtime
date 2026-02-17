# Agent Context: tiny-container-runtime (tcr)

## Project Goal

Build a tiny container runtime for resource-limited embedded devices. The workflow is split:
- **Build machine** (normal PC): pull images, flatten, package into squashfs
- **Target device** (embedded): mount squashfs, configure container, run with crun

> **History**: The initial design was prototyped with shell scripts in `experiments/`.
> That folder (including its `agent.md`) is historical and will be removed.
> This document is the authoritative reference.

## Current Implementation Status

The following components are implemented. The higher-level daemon (`tcrd`) and CLI client (`tcr`) are not yet implemented.

1. **`host_tools/tcr-create-image.sh`** — build-machine tool to pull, unpack, and package OCI images into squashfs. See [docs/create_image.md](docs/create_image.md).
2. **`src/network/dns_forwarder.{c,h}`** — lightweight event-loop-based UDP DNS forwarder. Each NAT network creates its own instance on the gateway address. See [docs/dns_forwarder.md](docs/dns_forwarder.md).
3. **`src/network/nat_network.{c,h}` / `nat_network_manager.{c,h}`** — NAT network management with nftables. Creates bridge + veth networking, IP allocation, network namespaces, and includes a built-in DNS forwarder per network.
4. **`src/network/port_forwarder.{c,h}`** — nftables-based DNAT port forwarding for containers.
5. **`src/image/image_manager.{c,h}`** — squashfs image lifecycle manager (load, mount, query, persist, remove). See [docs/image_manager.md](docs/image_manager.md).
6. **`src/resource/`** — default seccomp profile embedded into the binary via `ld -r -b binary`. See [docs/seccomp_resource.md](docs/seccomp_resource.md).
7. **`src/container/crun_config.{c,h}`** — OCI runtime config builder/manipulator for crun. Applies security defaults (capabilities, namespaces, seccomp), default mounts, and provides mutation APIs. See [docs/crun_config.md](docs/crun_config.md).
8. **`src/container/container_manager.{c,h}`** — full container lifecycle manager. Supports detached and interactive modes, overlayfs, NAT networking, port forwarding, restart persistence, and process monitoring via pidfd. See [docs/container_manager.md](docs/container_manager.md).
9. **`src/common/utils.{c,h}`** — shared utility functions (`path_join`, `load_json_file`, `rmdir_recursive`) used across modules.

---

## tcr-create-image.sh

Build-machine script: pulls an OCI image, unpacks it into a flat rootfs bundle, and packages it into a squashfs file (zstd compressed).

Uses `skopeo` → `umoci` → `mksquashfs` pipeline. Generates `image-info.json` (v1) metadata inside the squashfs.

Detail design: [docs/create_image.md](docs/create_image.md)

---

## Networking (`src/network/`)

### NAT Network (`nat_network.{c,h}`, `nat_network_manager.{c,h}`)

Manages NAT networks for container connectivity. Each network consists of a Linux bridge, nftables masquerade rules, IP address allocation (bitmap-based), and a built-in DNS forwarder on the gateway address.

- `nat_network_manager` — manages multiple named networks; creates on demand via `get_network()`
- `nat_network` — single network: bridge setup, IP allocation/reservation, network namespace creation (veth pair + bridge attachment), DNS forwarder
- Network namespaces named `tcr-<container_id>` are connected to the bridge with a veth pair

### DNS Forwarder (`dns_forwarder.{c,h}`)

A lightweight UDP DNS forwarder integrated into each NAT network. Runs on the gateway address (e.g. `10.88.0.1:53`). Zero threads, zero blocking calls — integrates with **tev** event loop.

- Resolves container names (`tcr-*`) to container IPs via a runtime lookup table (inter-container discovery)
- Forwards all other queries transparently to the host's upstream resolvers
- Containers get `nameserver <gateway>` in their generated resolv.conf

Detail design: [docs/dns_forwarder.md](docs/dns_forwarder.md)

### Port Forwarder (`port_forwarder.{c,h}`)

nftables-based DNAT port forwarding. Creates rules to forward `listen_ip:listen_port` → `target_ip:target_port` for TCP and/or UDP. Rules are labeled with a group ID (`tcr-<container_id>`) for batch cleanup.

---

## Image Manager (`src/image/`)

Manages squashfs container images on the target device: loading, mounting via loop device, querying by digest or name+tag, unmounting, and removal. Persistent across restarts — writes `image-runtime-info.json` per image and rebuilds state on startup.

- O(1) lookup by digest or `name:tag` using tev hash maps
- Loop device management with `LO_FLAGS_AUTOCLEAR`
- Strict JSON validation, mmap-based file loading
- Tag collision handling: new image takes the tag, old image keeps running without tag

Detail design: [docs/image_manager.md](docs/image_manager.md)

---

## Container Config (`src/container/crun_config.{c,h}`)

Builds and manipulates OCI runtime-spec `config.json` objects for crun. Reads the skeleton config from an image bundle, patches in security defaults, and provides mutation APIs for customization.

- Capabilities: 14 Docker-default caps across all 5 sets
- Namespaces: pid, ipc, uts, mount, network
- Seccomp: embedded containers/common profile converted to OCI format at runtime (architecture-filtered, conditional entries stripped)
- Default mounts: /proc, /dev, /dev/pts, /dev/shm, /dev/mqueue, /sys
- Config-only — no filesystem or network side effects

Detail design: [docs/crun_config.md](docs/crun_config.md)

---

## Container Manager (`src/container/container_manager.{c,h}`)

Full container lifecycle manager. Creates, starts, stops, restarts, monitors, and removes containers. Supports two modes:

- **Detached mode** — daemon fork+exec's crun, monitors via pidfd, handles restart policies and auto-remove
- **Interactive mode** — returns crun argv for client-side execution, daemon monitors the client pid

Key features:
- **Overlayfs** — read-write containers get an overlay (lower=image rootfs, upper/work/merged in container dir)
- **NAT networking** — IP allocation, network namespace, DNS registration, port forwarding via nat_network
- **Restart persistence** — `meta.json` persists container metadata; on daemon restart, eligible containers (detached + restart_policy != NEVER) are automatically restored and started
- **Process monitoring** — `pidfd_open()` + tev read handler for reliable exit detection
- **Crash safety** — `prctl(PR_SET_PDEATHSIG, SIGKILL)` ensures container dies if daemon crashes

Detail design: [docs/container_manager.md](docs/container_manager.md)

---

## Project Layout

```
host_tools/
  tcr-create-image.sh       # [build PC] pull + unpack + package → .sqfs

src/
  tcrd.c                     # target device daemon (C) — not yet implemented
  tcr.c                      # CLI client (C) — not yet implemented
  common/
    list.h                   # Linux kernel-style intrusive linked list
    bitmap.c                 # dynamic bitmap for IP allocation
    bitmap.h
    utils.h                  # shared utilities (path_join, load_json_file, rmdir_recursive)
    utils.c
  container/
    crun_config.c            # OCI runtime config builder for crun
    crun_config.h
    container_manager.c      # full container lifecycle manager
    container_manager.h
  image/
    image_manager.c          # squashfs image lifecycle manager
    image_manager.h
  network/
    dns_forwarder.c          # DNS forwarder (built into each NAT network)
    dns_forwarder.h
    nat_network.c            # single NAT network (bridge, IP, netns, DNS)
    nat_network.h
    nat_network_manager.c    # manages multiple named NAT networks
    nat_network_manager.h
    nft_helper.c             # nftables helper (table/chain/rule management)
    nft_helper.h
    port_forwarder.c         # nftables DNAT port forwarding
    port_forwarder.h
  resource/
    seccomp.json             # default seccomp profile (compacted)
    seccomp_json.h           # C header for embedded JSON symbols
    CMakeLists.txt           # builds libseccomp_resource.a

docs/
  container_manager.md       # container manager design document
  create_image.md            # tcr-create-image.sh design document
  crun_config.md             # crun_config design document
  dns_forwarder.md           # DNS forwarder design document
  image_manager.md           # image manager design document
  seccomp_resource.md        # seccomp embedding design document

test/
  test_container_manager.c   # container manager tests (18 tests)
  test_crun_config.c         # crun_config unit tests (11 tests)
  test_dns_forwarder.c       # DNS forwarder unit tests
  test_image_manager.c       # image manager integration tests
  test_nat_network.c         # NAT network tests
  test_nat_network_manager.c # NAT network manager tests
  test_port_forwarder.c      # port forwarder tests
  test_seccomp_resource.c    # seccomp embedding validation test
  test_util.h                # shared test macros (CHECK) and helpers (test_get_data_dir)
  run_test_container_manager.sh  # container manager test runner (valgrind)
  run_test_crun_config.sh    # crun_config test runner (valgrind)
  run_test_dns_forwarder.sh  # DNS forwarder test runner (valgrind)
  run_test_nat_network.sh    # NAT network test runner (valgrind)
  run_test_nat_network_manager.sh  # NAT network manager test runner (valgrind)
  run_test_port_forwarder.sh # port forwarder test runner (valgrind)
  run_image_manager_test.sh  # image manager test runner (valgrind)
```

### Testing

> **HTTP Proxy**: Before running tests in a new session, ask the user whether
> an HTTP proxy needs to be configured. Some test scripts pull container
> images from the internet (e.g. `run_image_manager_test.sh`,
> `run_test_crun_config.sh`). If the `http_proxy` / `https_proxy`
> environment variables are set, use `sudo -E` instead of plain `sudo`
> so the proxy settings are preserved under root.

Tests live in `test/` and are built with CMake:

```bash
cd test/build && cmake .. && make -j$(nproc)
```

Test data (temporary roots, image mounts, etc.) is written to `test/data/`
(created automatically by `test_get_data_dir()` in `test_util.h`).
This directory is git-ignored.

Tests that require root (mount, netns, nftables) have wrapper scripts:

| Script | What it tests | Needs root | Needs network |
|--------|--------------|------------|---------------|
| `run_test_container_manager.sh` | container_manager (+ valgrind) | yes | yes (pulls image on first run) |
| `run_test_crun_config.sh` | crun_config (+ valgrind) | yes | yes (pulls image on first run) |
| `run_image_manager_test.sh` | image_manager (+ valgrind) | yes | yes (pulls image on first run) |
| `run_test_nat_network.sh` | NAT network (+ valgrind) | yes | no |
| `run_test_nat_network_manager.sh` | NAT network manager (+ valgrind) | yes | no |
| `run_test_port_forwarder.sh` | port forwarder (+ valgrind) | yes | no |
| `run_test_dns_forwarder.sh` | DNS forwarder (+ valgrind) | no | yes (upstream forwarding tests) |

Non-root tests can be run directly:

```bash
./build/test_seccomp_resource
```

### Coding rules

1. **No arbitrary magic-number limits on dynamic data.**
   Never use a fixed-size stack array (e.g. `uint64_t buf[128]`) to collect
   items whose count has no hard upper bound. Use `malloc`/`realloc` instead.
   A fixed buffer is acceptable **only** when its size is derived from a
   proven cap (e.g. `INET_ADDRSTRLEN`, `PATH_MAX`, `IFNAMSIZ`,
   `MAX_RULE_HANDLES` = exactly 4 protocol×direction combinations).

2. **No fixed `snprintf` buffers for unbounded content.**
   When formatting strings that include user-supplied or variable-length
   data (table names, comments, group IDs, etc.), use `asprintf` instead of
   `snprintf` into a stack buffer. Fixed buffers are fine only when every
   field has a proven maximum length.

### Key constraints

1. **`umoci unpack` needs root** — preserves file ownership (uid/gid) via `lchown`.
2. **squashfs as image format** — read-only, highly compressed, supports random access, works as overlayfs lowerdir. Chosen for embedded distribution.
3. **squashfs mount requires loop devices** — kernel needs `loop` and `squashfs` modules.
