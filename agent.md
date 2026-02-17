# Agent Context: tiny-container-runtime (tcr)

## Project Goal

Build a tiny container runtime for resource-limited embedded devices. The workflow is split:
- **Build machine** (normal PC): pull images, flatten, package into squashfs
- **Target device** (embedded): mount squashfs, configure container, run with crun

> **History**: The initial design was prototyped with shell scripts in `experiments/`.
> That folder (including its `agent.md`) is historical and will be removed.
> This document is the authoritative reference.

## Current Implementation Status

Only the following components are implemented so far. The rest of the runtime (container lifecycle, networking setup, security patching, etc.) will be migrated from the experimental scripts incrementally.

1. **`host_tools/tcr-create-image.sh`** — build-machine tool to pull, unpack, and package OCI images into squashfs. See [docs/create_image.md](docs/create_image.md).
2. **`src/network/dns_forwarder.{c,h}`** — lightweight event-loop-based UDP DNS forwarder for the NAT gateway. See [docs/dns_forwarder.md](docs/dns_forwarder.md).
3. **`src/image/image_manager.{c,h}`** — squashfs image lifecycle manager (load, mount, query, persist, remove). See [docs/image_manager.md](docs/image_manager.md).
4. **`src/resource/`** — default seccomp profile embedded into the binary via `ld -r -b binary`. See [docs/seccomp_resource.md](docs/seccomp_resource.md).
5. **`src/container/crun_config.{c,h}`** — OCI runtime config builder/manipulator for crun. Applies security defaults (capabilities, namespaces, seccomp), default mounts, and provides mutation APIs. See [docs/crun_config.md](docs/crun_config.md).
6. **`src/common/utils.{c,h}`** — shared utility functions (`path_join`, `load_json_file`) used by image_manager and crun_config.

---

## tcr-create-image.sh

Build-machine script: pulls an OCI image, unpacks it into a flat rootfs bundle, and packages it into a squashfs file (zstd compressed).

Uses `skopeo` → `umoci` → `mksquashfs` pipeline. Generates `image-info.json` (v1) metadata inside the squashfs.

Detail design: [docs/create_image.md](docs/create_image.md)

---

## DNS Forwarder (`src/network/`)

A lightweight UDP DNS forwarder intended to run on the NAT gateway (`10.88.0.1:53`). Integrates with **tev** (tiny event loop) — zero threads, zero blocking calls.

- Resolves container names (`tcr-*`) to container IPs via a runtime lookup table (inter-container discovery)
- Forwards all other queries transparently to the host's upstream resolvers
- Containers only need `nameserver 10.88.0.1`

Detail design: [docs/dns_forwarder.md](docs/dns_forwarder.md)

---

## Image Manager (`src/image/`)

Manages squashfs container images on the target device: loading, mounting via loop device, querying by digest or name+tag, unmounting, and removal. Persistent across restarts — writes `image-runtime-info.json` per image and rebuilds state on startup.

- Exclusive access via `flock` on `<root>/.images_lock`
- O(1) lookup by digest or `name:tag` using tev hash maps
- Loop device management with `LO_FLAGS_AUTOCLEAR`
- Strict JSON validation, mmap-based file loading
- Tag collision handling: new image takes the tag, old image keeps running without tag

Detail design: [docs/image_manager.md](docs/image_manager.md)

---

## Container Config (`src/container/`)

Builds and manipulates OCI runtime-spec `config.json` objects for crun. Reads the skeleton config from an image bundle, patches in security defaults, and provides mutation APIs for customization.

- Capabilities: 14 Docker-default caps across all 5 sets
- Namespaces: pid, ipc, uts, mount, network
- Seccomp: embedded containers/common profile converted to OCI format at runtime (architecture-filtered, conditional entries stripped)
- Default mounts: /proc, /dev, /dev/pts, /dev/shm, /dev/mqueue, /sys
- Config-only — no filesystem or network side effects

Detail design: [docs/crun_config.md](docs/crun_config.md)

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
    utils.h                  # shared utilities (path_join, load_json_file)
    utils.c
  container/
    crun_config.c            # OCI runtime config builder for crun
    crun_config.h
  image/
    image_manager.c          # squashfs image lifecycle manager
    image_manager.h
  network/
    dns_forwarder.c          # DNS forwarder for NAT gateway
    dns_forwarder.h
  resource/
    seccomp.json             # default seccomp profile (compacted)
    seccomp_json.h           # C header for embedded JSON symbols
    CMakeLists.txt           # builds libseccomp_resource.a

docs/
  create_image.md            # tcr-create-image.sh design document
  crun_config.md             # crun_config design document
  dns_forwarder.md           # DNS forwarder design document
  image_manager.md           # image manager design document
  seccomp_resource.md        # seccomp embedding design document

test/
  test_crun_config.c         # crun_config unit tests (11 tests)
  test_dns_forwarder.c       # DNS forwarder unit tests
  test_image_manager.c       # image manager integration tests
  test_seccomp_resource.c    # seccomp embedding validation test
  run_test_crun_config.sh    # crun_config test runner (valgrind)
  run_image_manager_test.sh  # test runner (creates test sqfs, runs under valgrind)
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
