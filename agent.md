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

## Project Layout

```
host_tools/
  tcr-create-image.sh       # [build PC] pull + unpack + package → .sqfs

src/
  tcrd.c                     # target device daemon (C) — not yet implemented
  tcr.c                      # CLI client (C) — not yet implemented
  network/
    dns_forwarder.c          # DNS forwarder for NAT gateway
    dns_forwarder.h

docs/
  create_image.md            # tcr-create-image.sh design document
  dns_forwarder.md           # DNS forwarder design document

test/
  test_dns_forwarder.c       # DNS forwarder unit tests
```

### Key constraints

1. **`umoci unpack` needs root** — preserves file ownership (uid/gid) via `lchown`.
2. **squashfs as image format** — read-only, highly compressed, supports random access, works as overlayfs lowerdir. Chosen for embedded distribution.
3. **squashfs mount requires loop devices** — kernel needs `loop` and `squashfs` modules.
