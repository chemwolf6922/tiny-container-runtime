# Container Manager Design

## Purpose

Manages the full lifecycle of containers on the target device: creation, starting, stopping, restart, monitoring, and cleanup. Supports both **detached** (daemon-managed background) and **interactive** (client-driven foreground) container modes. Persists container metadata to disk for automatic restart on daemon restart.

**Location**: `src/container/container_manager.h`, `src/container/container_manager.c`

**Dependencies**: `crun_config` (OCI config builder), `image_manager` (image lifecycle), `nat_network_manager` (NAT networking), `port_forwarder` (nftables port forwarding), `dns_forwarder` (container DNS, via nat_network), `libcjson` (JSON), `libtev` (event loop)

## Architecture

```
container_manager_new(tev, img_manager, nat_manager, root_path)
  ├─ mkdir <root>/containers/
  ├─ list_head_init (empty container list)
  └─ restore_containers()
       └─ for each dir in <root>/containers/:
            ├─ read meta.json
            ├─ skip if not (detached && restart_policy != NEVER)
            ├─ find image by digest, mount if needed
            ├─ allocate container_s, fill fields from meta
            ├─ restore networking (reserve IP, create netns, port forwarders, DNS)
            └─ container_start() → fork+exec crun

container_manager_create_container(mgr, args)
  ├─ resolve image (by name+tag or digest)
  ├─ generate random 16-hex-char ID
  ├─ mkdir <root>/containers/<id>/
  ├─ build OCI config via crun_config
  │    ├─ set rootfs (overlay merged dir or image rootfs)
  │    ├─ set readonly / terminal / command / env
  │    ├─ add bind mounts, tmpfs mounts
  │    └─ set network namespace
  ├─ setup overlay dirs (if read-write)
  ├─ setup networking (if NAT network requested)
  │    ├─ allocate IP from nat_network
  │    ├─ create network namespace
  │    ├─ generate resolv.conf (gateway as nameserver)
  │    ├─ register DNS entry (tcr-<id>)
  │    └─ create port forwarders
  ├─ write config.json (OCI runtime config)
  ├─ write meta.json (restart persistence metadata)
  └─ add to manager's container list

container_start(c)  [detached mode]
  ├─ mount_overlay() if needed
  ├─ fork()
  ├─ child: prctl(PR_SET_PDEATHSIG, SIGKILL), redirect stdio to /dev/null
  │         execlp("crun", "run", "--bundle", ..., "--config", ..., id)
  └─ parent: setup_process_monitor(pidfd) → tev read handler

container_get_crun_args(c)  [interactive mode]
  ├─ mount_overlay() if needed
  └─ return argv: ["crun", "run", "--bundle", <path>, "--config", <path>, <id>]

container_stop(c, immediately)
  ├─ if immediately: kill(SIGKILL) + waitpid
  └─ else: kill(SIGTERM) + tev timeout → on_stop_timeout → SIGKILL

container_remove(c)
  ├─ force stop if running
  ├─ cleanup_process_monitor + umount_overlay + cleanup_network
  ├─ rmdir_recursive(container_dir)
  └─ free container
```

## On-disk Layout

```
<root>/
  containers/
    <id>/
      config.json           # OCI runtime config (for crun)
      meta.json             # container metadata (for restart persistence)
      resolv.conf           # generated DNS config (if networked)
      overlay/              # (if read-write)
        upper/              # overlayfs upper layer (container writes)
        work/               # overlayfs work directory
        merged/             # overlayfs merged mount point
```

## Container Modes

### Detached Mode

The daemon manages the container lifecycle. On `container_start()`:
1. `fork()` + `execlp("crun", "run", ...)` in child
2. Child calls `prctl(PR_SET_PDEATHSIG, SIGKILL)` — if the daemon dies (even from SIGKILL), the kernel kills the container process. No orphaned containers.
3. Parent monitors via `pidfd_open()` — the pidfd becomes readable when the child exits
4. `tev_set_read_handler()` on pidfd → `on_process_exit()` callback

### Interactive Mode

The client runs crun directly. `container_get_crun_args()` returns the exact argv to `execvp`. The daemon doesn't own the process but can monitor it via `container_monitor_process()`.

Interactive mode rejects containers with `restart_policy != NEVER` (restart requires daemon ownership of the process).

### Exec Mode

`container_get_exec_args()` builds a `crun exec` argv for running a command inside a running container. Supports `-d` (detach), `-t` (TTY), and `-e KEY=VALUE` (environment variables). The client `execvp`'s into crun exec, which enters the container's namespaces and runs the command. All exec processes are children of the container's PID namespace and die when the container stops.

## Overlay Filesystem

For read-write containers, overlayfs provides a writable layer on top of the read-only image:

```
overlay mount:
  lowerdir  = <image_bundle>/rootfs    (read-only image)
  upperdir  = <container_dir>/overlay/upper   (container writes)
  workdir   = <container_dir>/overlay/work
  merged    = <container_dir>/overlay/merged  (container sees this)
```

The OCI config's `root.path` is set to the merged directory. Read-only containers skip overlay entirely and use the image's rootfs directly with `root.readonly = true`.

## Networking

When a NAT network is requested (`container_args_set_nat_network`):

1. **IP allocation** — `nat_network_allocate_ip()` assigns an IP from the subnet
2. **Network namespace** — `nat_network_create_network_namespace()` creates a netns named `tcr-<id>` connected to the NAT bridge
3. **DNS** — resolv.conf is generated with the gateway IP as nameserver; the container is registered in the nat_network's built-in DNS forwarder as `tcr-<id>` → allocated IP
4. **Port forwarding** — `port_forwarder_new()` creates nftables DNAT rules for each forwarded port

Cleanup reverses all steps: remove DNS entry, free port forwarders, remove netns, release IP.

## Process Monitoring

Uses Linux `pidfd_open()` (kernel 5.3+) for reliable process exit detection:

```c
pidfd = syscall(SYS_pidfd_open, pid, 0);
tev_set_read_handler(tev, pidfd, on_process_exit, container);
```

When the pidfd becomes readable, the process has exited. The callback:
1. `waitid(P_PIDFD, ...)` to reap exit status
2. Cleans up the pidfd handler
3. Unmounts overlay
4. Checks restart policy → restart or auto-remove

## Restart Persistence

### meta.json

Written alongside `config.json` during container creation. Contains all metadata needed to restore the container:

```json
{
  "id": "a1b2c3d4e5f6g7h8",
  "name": "my-container",
  "detached": true,
  "auto_remove": false,
  "readonly": false,
  "restart_policy": 2,
  "stop_timeout_ms": 10000,
  "bundle_path": "/path/to/image/bundle",
  "image_digest": "sha256:...",
  "nat_network_name": "tcr_default",
  "netns_name": "tcr-a1b2c3d4e5f6g7h8",
  "allocated_ip": "10.88.0.5",
  "port_forwards": [
    {
      "host_ip": "0.0.0.0",
      "host_port": 8080,
      "container_port": 80,
      "protocol": 1
    }
  ]
}
```

### Restore on Startup

When `container_manager_new()` is called, `restore_containers()` scans the containers directory:
- For each subdirectory with a `meta.json`: parse it
- **Skip** if not `detached` or `restart_policy == NEVER`
- **Skip** if the image digest is not found in the image manager
- Otherwise: reconstruct the container, re-setup networking, and start it

Non-restartable containers are left on disk untouched (not cleaned up, not loaded into memory).

### Restart Policy

| Policy | Value | Behavior |
|--------|-------|----------|
| `CONTAINER_RESTART_POLICY_NEVER` | 0 | Never restart. Container exits → stopped (or auto-removed). |
| `CONTAINER_RESTART_POLICY_UNLESS_STOPPED` | 1 | Restart on exit unless explicitly stopped via `container_stop()`. |
| `CONTAINER_RESTART_POLICY_ALWAYS` | 2 | Always restart on exit, including after daemon restart. |

## Graceful Stop

`container_stop(c, false)` sends `SIGTERM` and starts a timer (default 10s, configurable via `container_args_set_stop_timeout`). If the container doesn't exit within the timeout, `on_stop_timeout` sends `SIGKILL`.

`container_stop(c, true)` sends `SIGKILL` immediately and waits synchronously.

## Key Design Decisions

### pidfd over SIGCHLD

`SIGCHLD` is process-global and interferes with other signal handling. `pidfd_open()` provides a per-process file descriptor that integrates cleanly with the tev event loop. Available since Linux 5.3 — acceptable for the target environment.

### PR_SET_PDEATHSIG for crash safety

The child calls `prctl(PR_SET_PDEATHSIG, SIGKILL)` after fork and before exec. This guarantees that if the daemon process dies for any reason (including SIGKILL), the kernel sends SIGKILL to the container process. No orphaned containers even in worst-case daemon crashes.

A race exists between `fork()` and `prctl()` — if the parent dies in that window, the death signal won't be set. Detected by checking `getppid() == 1` (reparented to init) after prctl.

### Overlay dirs survive daemon restart

The overlay directories (upper, work, merged) persist on disk. When restoring a container, the dirs already exist from the original creation. The overlay just needs to be re-mounted. This preserves container filesystem state across daemon restarts.

### Config-only in create, side-effects in start

`container_manager_create_container()` sets up all filesystem and network state but does not launch any process. `container_start()` does the fork+exec. This separation allows inspecting the container state before starting and enables the interactive mode path (`container_get_crun_args`).

### Port forward specs persisted separately

Port forwarding parameters (host_ip, host_port, container_port, protocol) are stored in `port_forward_specs[]` alongside the opaque `port_forwarder` handles. This allows serializing them to meta.json without requiring a getter API on the opaque port_forwarder type.

## Public API Summary

### Manager Lifecycle

| Function | Description |
|---|---|
| `container_manager_new(tev, img_mgr, nat_mgr, root_path)` | Create manager, restore eligible containers |
| `container_manager_free(manager)` | Kill all detached containers, cleanup, free |
| `container_manager_get_image_ref_count(mgr, img)` | Count containers using an image |

### Container Arguments (Builder Pattern)

| Function | Description |
|---|---|
| `container_args_new()` / `container_args_free(args)` | Create / free args builder |
| `container_args_set_name(args, name)` | Set container name |
| `container_args_set_image(args, ref)` | Set image reference (id or name:tag) |
| `container_args_set_readonly(args, ro)` | Read-only rootfs (no overlay) |
| `container_args_set_terminal_mode(args, tty)` | Terminal mode |
| `container_args_set_detached(args, detached)` | Detached (daemon-managed) mode |
| `container_args_set_auto_remove(args, auto_remove)` | Auto-remove on exit |
| `container_args_set_restart_policy(args, policy)` | Restart policy |
| `container_args_set_stop_timeout(args, ms)` | Graceful stop timeout |
| `container_args_set_command(args, argc, argv)` | Override command |
| `container_args_set_nat_network(args, name)` | Join NAT network |
| `container_args_add_bind_mount(args, src, dst, ro)` | Add bind mount |
| `container_args_add_tmpfs_mount(args, dst, size)` | Add tmpfs mount |
| `container_args_add_env(args, key, value)` | Add environment variable |
| `container_args_add_port_forwarding(args, hip, hp, cp, proto)` | Add port forward |

### Container Lifecycle

| Function | Description |
|---|---|
| `container_manager_create_container(mgr, args)` | Create container (no start) |
| `container_start(c)` | Start detached container |
| `container_stop(c, immediately)` | Stop container (graceful or immediate) |
| `container_remove(c)` | Force stop + remove all resources + delete from disk |
| `container_get_crun_args(c, argv, argc)` | Get crun argv for interactive mode |
| `container_get_exec_args(c, detach, tty, env, env_count, cmd, cmd_count, argv, argc)` | Get crun exec argv for exec mode |
| `container_free_crun_args(argv, argc)` | Free argv from above (works for both run and exec) |
| `container_monitor_process(c, pid)` | Monitor externally-started process |

### Query

| Function | Description |
|---|---|
| `container_manager_find_container(mgr, name_or_id)` | Find by name or ID |
| `container_manager_foreach_container_safe(mgr, fn, ud)` | Iterate all containers |
| `container_get_id(c)` / `container_get_name(c)` | Get ID / name |
| `container_is_running(c)` / `container_is_detached(c)` | Query state |

## Testing

Tests are in `test/test_container_manager.c`, run via `test/run_test_container_manager.sh`.

**Requirements**: root (for overlay mount, network namespace, nftables), a test squashfs image (auto-created by the test script).

**Test cases**:

| Test | What it verifies |
|---|---|
| `test_args_new_free` | Args builder create/free, NULL safety |
| `test_args_set_name` | Name setter, NULL rejection |
| `test_args_image_mutual_exclusion` | Digest and name+tag are mutually exclusive |
| `test_args_setters` | All builder setters work correctly |
| `test_manager_new_free` | Manager create/free, NULL arg rejection |
| `test_null_safety` | All public APIs handle NULL inputs gracefully |
| `test_create_no_image` | Create fails without image or with nonexistent image |
| `test_create_container_readonly` | Read-only container, getters, find by ID |
| `test_create_container_rw_overlay` | Read-write container with overlay dirs |
| `test_create_container_with_options` | Command, env, tmpfs, terminal in config.json |
| `test_multiple_containers` | Multiple containers, ref counting, foreach, remove |
| `test_find_by_digest` | Create container by image digest |
| `test_get_crun_args_interactive` | Interactive mode argv construction |
| `test_get_crun_args_rejects_restart_policy` | Interactive mode rejects restart policy |
| `test_start_rejects_non_detached` | `container_start` rejects non-detached containers |
| `test_stop_not_running` | Stopping a non-running container is a no-op |
| `test_detached_container_lifecycle` | Full detached lifecycle: create → start → stop → remove |
| `test_manager_free_kills_detached` | Manager free kills running detached containers |
| `test_meta_json_written` | meta.json written with correct fields on create |
| `test_meta_json_not_restartable_ignored` | Non-restartable containers not restored on restart |
| `test_restart_on_manager_recreate` | Restartable container restored and started on new manager |
| `test_unless_stopped_not_restored_after_stop` | UNLESS_STOPPED + explicit stop not restored on restart |
| `test_always_restored_after_stop` | ALWAYS policy still restored after explicit stop |

All tests run under valgrind (60,139 allocs, 60,139 frees, 0 leaks, 0 errors).
