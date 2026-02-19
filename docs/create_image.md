# tcr-create-image.sh

Build-machine script that pulls an OCI container image, unpacks it into a flat rootfs bundle, and packages it into a squashfs file.

**Location**: `host_tools/tcr-create-image.sh`

**Dependencies**: `skopeo`, `umoci`, `mksquashfs` (squashfs-tools), `jq`, `xxhsum` (xxHash CLI)

## Usage

```
tcr-create-image.sh [OPTIONS] <image>

Options:
  -o, --output <path>    Output .sqfs file path (default: ./<name>.sqfs)
  -w, --working <dir>    Working/build directory (default: ./tcr-build)
  -f, --force            Overwrite existing output/build without prompting
  -h, --help             Show help

Examples:
  tcr-create-image.sh docker.io/library/alpine:latest
  tcr-create-image.sh -o images/alpine.sqfs alpine:latest
  tcr-create-image.sh -w /tmp/tcr-build -o out.sqfs myregistry.io/app:v2
```

## Pipeline

1. **Pull** — `skopeo copy docker://<image> oci:<work>/oci-image:<tag>`
2. **Unpack** — `sudo umoci unpack --image <oci>:<tag> <stage>/bundle` (needs root for `lchown`)
3. **Metadata** — generate `image-info.json` in the staging area
4. **Package** — `sudo mksquashfs <stage> <output>.sqfs -comp zstd`
5. **Cleanup** — `trap cleanup EXIT` removes the build directory on any exit (success or failure)

## image-info.json (v1)

```json
{
    "version": 1,
    "image": {
        "id": "a1b2c3d4e5f6g7h8",
        "registry": "docker.io",
        "repository": "library/alpine",
        "tag": "latest",
        "digest": "sha256:...",
        "arch": "amd64"
    },
    "bundlePath": "bundle",
    "created": 1739500800
}
```

- `version`: integer, incremented only on breaking schema changes.
- `id`: 64-bit xxHash of the digest, as a 16-character hex string. Used as the primary image identifier.
- `created`: Unix timestamp (seconds since epoch, always UTC).

## squashfs image contents

```
<name>.sqfs (squashfs, zstd compressed)
  image-info.json            # image metadata
  bundle/
    rootfs/                  # flat filesystem
    config.json              # OCI runtime config (umoci output, unpatched)
```

## Design notes

- All paths default relative to `$PWD`, not the script location — suitable for end users running the tool from anywhere.
- Pre-flight dependency check: errors immediately with a list of missing tools rather than failing mid-pipeline.
- Refuses to overwrite existing output or non-empty build directory unless `-f` is passed.
- `umoci unpack` needs root because it preserves file ownership (uid/gid) via `lchown`.
