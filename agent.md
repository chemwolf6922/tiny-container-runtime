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

## Project Layout

```
host_tools/
  tcr-create-image.sh       # [build PC] pull + unpack + package → .sqfs

src/
  tcrd.c                     # target device daemon (C) — not yet implemented
  tcr.c                      # CLI client (C) — not yet implemented
  common/
    list.h                   # Linux kernel-style intrusive linked list
  image/
    image_manager.c          # squashfs image lifecycle manager
    image_manager.h
  network/
    dns_forwarder.c          # DNS forwarder for NAT gateway
    dns_forwarder.h

docs/
  create_image.md            # tcr-create-image.sh design document
  dns_forwarder.md           # DNS forwarder design document
  image_manager.md           # image manager design document

test/
  test_dns_forwarder.c       # DNS forwarder unit tests
  test_image_manager.c       # image manager integration tests
  run_image_manager_test.sh  # test runner (creates test sqfs, runs under valgrind)
```

### Key constraints

1. **`umoci unpack` needs root** — preserves file ownership (uid/gid) via `lchown`.
2. **squashfs as image format** — read-only, highly compressed, supports random access, works as overlayfs lowerdir. Chosen for embedded distribution.
3. **squashfs mount requires loop devices** — kernel needs `loop` and `squashfs` modules.
