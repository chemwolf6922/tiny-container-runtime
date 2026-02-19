# Image Manager Design

## Purpose

Manages the lifecycle of squashfs container images on the target device: loading, mounting (via loop device), querying, unmounting, and removal. Provides persistent state across restarts by writing metadata to disk and scanning on startup.

**Location**: `src/image/image_manager.h`, `src/image/image_manager.c`

**Dependencies**: `libtev` (map), `libcjson` (JSON parsing), Linux kernel modules: `loop`, `squashfs`

## Architecture

```
image_manager_new(root_path)
  ├─ mkdir <root>/
  ├─ mkdir <root>/images/
  ├─ flock <root>/.images_lock (exclusive, non-blocking)
  ├─ create digest_map + tag_map
  └─ manager_scan_existing()
       └─ for each UUID dir in <root>/images/:
            ├─ parse image-runtime-info.json → metadata
            ├─ check if mnt/ is a mountpoint
            │    └─ if mounted: parse image-info.json from squashfs
            └─ register into maps + linked list

image_manager_load(mgr, sqfs_path)
  ├─ resolve + validate path
  ├─ generate UUID → mkdir <root>/images/<uuid>/
  ├─ mkdir <root>/images/<uuid>/mnt/
  ├─ setup_loop(sqfs_path) → /dev/loopN
  ├─ mount -t squashfs -o ro /dev/loopN → mnt/
  ├─ parse image-info.json (inside squashfs)
  ├─ check duplicate digest
  ├─ write image-runtime-info.json (outside squashfs)
  └─ register into maps + linked list

image_manager_remove(mgr, img)
  ├─ unregister from maps + list
  ├─ umount + detach loop (if mounted)
  ├─ unlink runtime info, rmdir mnt/, rmdir uuid_dir/
  └─ free image
```

## On-disk Layout

```
<root>/
  .images_lock                          # flock for exclusive access
  images/
    <uuid-1>/
      image-runtime-info.json           # persisted metadata (outside squashfs)
      mnt/                              # squashfs mount point
        image-info.json                 # image metadata (inside squashfs, read-only)
        bundle/
          rootfs/                       # container root filesystem
          config.json                   # OCI runtime config
    <uuid-2>/
      ...
```

## Data Structures

### `struct image_manager_s` (opaque, typedef `image_manager` = pointer)

| Field       | Type            | Description                                      |
|-------------|-----------------|--------------------------------------------------|
| root_path   | `char *`        | Absolute path to the root directory              |
| images_dir  | `char *`        | `<root>/images/`                                 |
| lock_fd     | `int`           | File descriptor for `.images_lock` (flock)       |
| images      | `list_head`     | Intrusive linked list of all images              |
| id_map      | `map_handle_t`  | `id string → struct image_s*`                    |
| tag_map     | `map_handle_t`  | `"name:tag" → struct image_s*`                   |

### `struct image_s` (opaque, typedef `image` = pointer)

| Field            | Type       | Description                                        |
|------------------|------------|----------------------------------------------------|
| list             | `list_head`| Intrusive list node                                |
| sqfs_path        | `char *`   | Absolute path to the `.sqfs` file                  |
| uuid_dir         | `char *`   | `<root>/images/<uuid>/`                            |
| mount_path       | `char *`   | `<root>/images/<uuid>/mnt/`                        |
| runtime_info_path| `char *`   | Path to `image-runtime-info.json`                  |
| id               | `char *`   | xxh64 hash of the digest (16-char hex string)      |
| name             | `char *`   | `"registry/repository"` (e.g. `"docker.io/library/alpine"`) |
| tag              | `char *`   | Image tag (may be NULL if superseded)              |
| digest           | `char *`   | Content digest (e.g. `"sha256:..."`)               |
| arch             | `char *`   | Architecture (e.g. `"amd64"`, `"arm64"`)           |
| created          | `uint64_t` | Creation timestamp (Unix seconds)                  |
| mounted          | `bool`     | Whether currently mounted                          |
| loop_dev         | `char *`   | `/dev/loopN` when mounted, NULL otherwise          |
| bundle_path      | `char *`   | Absolute path to bundle dir (only when mounted)    |

## Key Design Decisions

### Squashfs via loop device

Squashfs cannot be mounted directly from a file — it requires a block device. The image manager uses Linux loop devices:

1. `ioctl(LOOP_CTL_GET_FREE)` — acquire a free loop device number
2. `ioctl(LOOP_SET_FD)` — attach the squashfs file to `/dev/loopN`
3. `ioctl(LOOP_SET_STATUS64)` with `LO_FLAGS_AUTOCLEAR` — auto-detach on last close after umount
4. `mount("/dev/loopN", mount_path, "squashfs", MS_RDONLY, NULL)`

`LO_FLAGS_AUTOCLEAR` ensures no loop device leak on crash: once the mount is gone, the loop device is freed automatically.

### Exclusive lock via flock

Only one `image_manager` instance can manage a given root path at a time. This is enforced with `flock(LOCK_EX | LOCK_NB)` on `<root>/.images_lock`. If another process already holds the lock, `image_manager_new()` fails immediately (non-blocking).

The lock is automatically released when the process exits or when `image_manager_free()` is called.

### Dual map indexing

Images are indexed by two maps for O(1) lookup:
- **id_map**: `id → image` — used by `image_manager_find_by_id()`
- **tag_map**: `"name:tag" → image` — used by `image_manager_find_by_name()`

Both maps use tev's `map_handle_t` (hash map with string keys + explicit key length).

The image id is a 16-character hex string computed as the 64-bit xxHash of the digest. This provides a short, unique identifier suitable for display and command-line use, replacing the unwieldy full digest string.

### Tag collision handling

When loading a new image with the same `name:tag` as an existing one, the old image's tag is set to NULL (it loses its tag) and its runtime info is updated on disk. The new image takes ownership of the tag in the tag map. The old image remains loaded and accessible by digest.

### Persistence via image-runtime-info.json

Each loaded image writes an `image-runtime-info.json` file outside the squashfs, containing:

```json
{
    "sqfsPath": "/path/to/image.sqfs",
    "id": "a1b2c3d4e5f6g7h8",
    "digest": "sha256:...",
    "name": "docker.io/library/alpine",
    "tag": "latest",
    "arch": "arm64",
    "created": 1739500800
}
```

On startup, `manager_scan_existing()` scans all UUID directories and rebuilds in-memory state from these files. If a mount is still active (detected via `/proc/self/mountinfo`), the authoritative `image-info.json` inside the squashfs is re-read instead.

### mmap-based JSON loading

JSON files are loaded via `mmap(MAP_PRIVATE)` + `cJSON_ParseWithLength()` instead of `read()` + `cJSON_Parse()`. This avoids manual buffer allocation and ensures the parser receives the exact file size, preventing buffer overruns on unterminated files.

### Strict JSON validation

Both `parse_image_info()` and `parse_runtime_info()` validate every mandatory field with `cJSON_IsString()` / `cJSON_IsNumber()`. Any missing or wrongly-typed field causes the parse to fail (goto bad pattern). No field is silently defaulted.

### Error rollback in registration

`manager_register_image()` returns `int` and checks `map_add()` return values for OOM. On failure:
1. If tag map insertion fails after digest map insertion, the digest entry is rolled back
2. If key allocation fails, the digest entry is rolled back
3. The linked list insertion (which cannot fail) only happens after both maps succeed

## Public API Summary

| Function | Description |
|----------|-------------|
| `image_manager_new(root_path)` | Create manager, acquire lock, scan existing images |
| `image_manager_free(mgr, umount_all)` | Free manager; optionally umount all images first |
| `image_manager_load(mgr, path)` | Load + mount a squashfs image, returns image handle |
| `image_manager_remove(mgr, img)` | Umount + remove image from disk and memory |
| `image_manager_mount_image(mgr, img)` | Mount an unmounted image |
| `image_manager_umount_image(mgr, img)` | Unmount a mounted image |
| `image_manager_foreach_safe(mgr, fn, data)` | Iterate all images (safe to remove during iteration) |
| `image_manager_find_by_id(mgr, id)` | O(1) lookup by id |
| `image_manager_find_by_name(mgr, name, tag)` | O(1) lookup by name+tag |
| `image_manager_find_by_id_or_name(mgr, ref)` | Convenience: try id, then parse name:tag |
| `image_get_id(img)` | Get image id (xxh64 hex string) |
| `image_get_name(img)` | Get `"registry/repository"` string |
| `image_get_tag(img)` | Get tag (may be NULL) |
| `image_get_created_at(img)` | Get creation timestamp |
| `image_get_digest(img)` | Get digest string |
| `image_get_mounted(img)` | Check if mounted |
| `image_get_bundle_path(img)` | Get bundle path (NULL if unmounted) |

## Testing

Tests are in `test/test_image_manager.c`, run via `test/run_image_manager_test.sh`.

**Requirements**: root (for mount/loop), a test squashfs image (auto-created by the test script using `tcr-create-image.sh`).

**Test cases** (8 total):
1. `test_new_and_free` — create and destroy manager
2. `test_lock_exclusive` — second manager on same root fails
3. `test_load_and_query` — load image, verify metadata and lookups
4. `test_duplicate_id_rejected` — loading same image twice fails
5. `test_mount_umount` — umount then remount an image
6. `test_remove` — remove image, verify cleanup
7. `test_foreach` — iterate over loaded images
8. `test_persistence` — destroy and re-create manager, verify images survive

All tests run under valgrind (784 allocs, 784 frees, 0 leaks, 0 errors).
