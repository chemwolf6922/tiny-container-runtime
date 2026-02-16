# Container Config (crun_config) Design

## Purpose

Builds and manipulates OCI runtime-spec `config.json` objects for use with `crun`. Reads a skeleton config from an image bundle, patches in security defaults (capabilities, namespaces, seccomp), default mounts, and provides functions to customize the config before container creation.

**Location**: `src/container/crun_config.h`, `src/container/crun_config.c`

**Dependencies**: `libcjson` (JSON manipulation), `libseccomp_resource` (embedded seccomp profile), `common/utils.{h,c}` (`path_join`, `load_json_file`)

## Architecture

```
crun_config_create(bundle_path)
  ├─ load <bundle_path>/config.json (via load_json_file)
  ├─ set root.readonly = true
  ├─ set process.terminal = false
  ├─ patch process.capabilities (14 Docker-default caps × 5 sets)
  ├─ patch linux.namespaces (pid, ipc, uts, mount, network)
  ├─ patch linux.seccomp (converted from embedded containers/common profile)
  └─ ensure default mounts (/proc, /dev, /dev/pts, /dev/shm, /dev/mqueue, /sys)

crun_config_set_*  / crun_config_add_*
  └─ modify the in-memory cJSON tree (no disk I/O)
```

The caller is responsible for writing the modified config to disk (via `cJSON_Print` + file write) before invoking `crun`.

## Config Defaults Applied by `crun_config_create`

### Capabilities

14 capabilities matching Docker defaults, applied to all 5 sets (bounding, effective, inheritable, permitted, ambient):

| Capability |
|---|
| `CAP_CHOWN` |
| `CAP_DAC_OVERRIDE` |
| `CAP_FSETID` |
| `CAP_FOWNER` |
| `CAP_MKNOD` |
| `CAP_NET_RAW` |
| `CAP_SETGID` |
| `CAP_SETUID` |
| `CAP_SETFCAP` |
| `CAP_SETPCAP` |
| `CAP_NET_BIND_SERVICE` |
| `CAP_SYS_CHROOT` |
| `CAP_KILL` |
| `CAP_AUDIT_WRITE` |

### Namespaces

Five namespaces are created by default: `pid`, `ipc`, `uts`, `mount`, `network`.

The network namespace is created without a path (new namespace per container). Use `crun_config_set_network_ns()` to join an existing namespace instead.

### Default Mounts

Added only if not already present in the skeleton config:

| Destination | Type | Source | Options |
|---|---|---|---|
| `/proc` | proc | proc | — |
| `/dev` | tmpfs | tmpfs | nosuid, strictatime, mode=755, size=65536k |
| `/dev/pts` | devpts | devpts | nosuid, noexec, newinstance, ptmxmode=0666, mode=0620 |
| `/dev/shm` | tmpfs | shm | nosuid, noexec, nodev, mode=1777, size=65536k |
| `/dev/mqueue` | mqueue | mqueue | nosuid, noexec, nodev |
| `/sys` | sysfs | sysfs | nosuid, noexec, nodev, ro |

### Seccomp Profile Conversion

The embedded `seccomp.json` (from `src/resource/`) uses the **containers/common** format. `crun_config_create` converts it to OCI `linux.seccomp` format at runtime:

1. **Architecture filtering** — `archMap` is filtered to the native architecture only (detected via `uname().machine` → `SCMP_ARCH_*` mapping). Sub-architectures from the matched entry are included.
2. **Conditional entry stripping** — Syscall entries with non-empty `includes` or `excludes` objects are skipped entirely. These are architecture- or capability-conditional rules that require runtime evaluation. The base (unconditional) entries cover the common case.
3. **Field stripping** — `includes`, `excludes`, `comment`, and `errno` fields are removed from each syscall entry.
4. **Field preservation** — `names`, `action` are always kept. `args` is kept only if non-empty. `errnoRet` is kept only if present and > 0.

Supported architecture mappings:

| `uname().machine` | `SCMP_ARCH_*` |
|---|---|
| `x86_64` | `SCMP_ARCH_X86_64` |
| `aarch64` | `SCMP_ARCH_AARCH64` |
| `armv7l` | `SCMP_ARCH_ARM` |
| `ppc64le` | `SCMP_ARCH_PPC64LE` |
| `s390x` | `SCMP_ARCH_S390X` |
| `mips64` | `SCMP_ARCH_MIPS64` |
| `riscv64` | `SCMP_ARCH_RISCV64` |

## Key Design Decisions

### Config-only, no side effects

All functions only manipulate the in-memory cJSON tree. No filesystem mounts, network setup, or process creation happens here. This separation keeps the module testable without root privileges (except for loading the test image).

### Skeleton config from bundle

The base `config.json` is read from the image bundle (created by `umoci unpack`). This preserves any image-specific settings (e.g. `process.args`, `process.env`, `process.cwd`) while patching in the security and mount defaults.

### goto-based cleanup in `build_oci_seccomp`

The seccomp conversion function manages multiple owned cJSON objects (`src`, `oci`, plus temporaries like `arch_array`, `syscalls`). A single `goto fail` label handles cleanup of the two long-lived objects, while temporaries are freed before attaching to `oci` or cleaned up inline when attachment fails.

### Comprehensive cJSON error checking

Every `cJSON_Create*`, `cJSON_Duplicate`, `cJSON_AddItemToObject`, `cJSON_AddItemToArray`, and `cJSON_Add*ToObject` return value is checked. On failure:
- Unattached items are freed immediately to prevent leaks
- The function returns an error (NULL or -1)

`cJSON_AddItemToObject` internally `strdup`s the key and can fail. If it returns false, the item is **not** adopted and must be freed by the caller.

### Idempotent default mounts

`ensure_default_mounts()` checks each default mount destination against the existing mounts array before adding. This prevents duplicates if the skeleton config already contains some of these mounts.

## Public API Summary

| Function | Description |
|---|---|
| `crun_config_create(bundle_path)` | Load skeleton config, apply security defaults, return cJSON tree |
| `crun_config_set_readonly(config, readonly)` | Set `root.readonly` |
| `crun_config_set_rootfs(config, rootfs_path)` | Set `root.path` |
| `crun_config_set_terminal_mode(config, is_tty)` | Set `process.terminal` |
| `crun_config_set_args(config, argc, argv)` | Set `process.args` |
| `crun_config_add_bind_mount(config, src, dst, ro)` | Append a bind mount with options `["bind"]` or `["bind", "ro"]` |
| `crun_config_add_tmpfs_mount(config, dst, size)` | Append a tmpfs mount with options `["nosuid", "nodev", "mode=1777", "size=<N>"]` |
| `crun_config_add_env(config, key, value)` | Append `"KEY=VALUE"` to `process.env` |
| `crun_config_set_network_ns(config, ns_path)` | Set `path` on the existing network namespace entry |

All mutating functions return `int` (0 = success, -1 = failure) except `crun_config_create` which returns `cJSON*` (NULL on failure). The returned cJSON tree must be freed with `cJSON_Delete()`.

## Testing

Tests are in `test/test_crun_config.c`, run via `test/run_test_crun_config.sh`.

**Requirements**: root (for squashfs mount during image loading), a test squashfs image (auto-created by the test script using `tcr-create-image.sh`).

**Test cases** (11 total):
1. `test_create_basic` — verify capabilities, namespaces, seccomp, default mounts, readonly, terminal
2. `test_set_readonly` — toggle readonly flag
3. `test_set_rootfs` — change root.path
4. `test_set_terminal_mode` — toggle process.terminal
5. `test_set_args` — set process.args
6. `test_add_bind_mount` — add bind mount, verify options
7. `test_add_tmpfs_mount` — add tmpfs mount, verify size option
8. `test_add_env` — add environment variable
9. `test_set_network_ns` — set network namespace path
10. `test_null_args` — all functions reject NULL inputs
11. `test_seccomp_no_conditional` — verify conditional seccomp entries are stripped

All tests run under valgrind (34,278 allocs, 34,278 frees, 0 leaks, 0 errors).
