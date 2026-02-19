# TCR Commands

## Overview

The `tcr` CLI is a thin pass-through client. All command parsing and execution happens in `tcrd`. The client sends `argv[1]` as the RPC method and `argv[2:]` as the args array, along with `pwd` and `pid`.

Commands use a flat `<noun> <verb>` or single-verb structure:

```
tcr run [options] <image> [command...]
tcr exec [options] <container> <command...>
tcr ps
tcr stop <container>
tcr kill <container>
tcr rm <container>
tcr image load <path>
tcr image ls
tcr image rm <ref>
tcr network ls
tcr network rm <name>
tcr help
```

## Argument Parsing

The daemon receives `params.args` (string array) and parses flags itself using a hand-rolled parser. No external library — keeps the binary small for embedded targets.

Path arguments (e.g. `image load ./foo.sqfs`, `-v ./data:/data`) are resolved by joining `params.pwd` with the relative path.

---

## Container Commands

### `tcr run [options] <image> [command...]`

Create and run a container.

**Default behavior**: interactive mode — the daemon returns `execArgs` and the client `execvp`'s into crun. The user gets a direct terminal to the container.

With `-d`: detached mode — the daemon fork+exec's crun, monitors via pidfd, and returns the container ID.

**Networking default**: every container joins the default NAT network (`tcr_default`) unless `--no-network` is specified.

#### Options

| Flag | Description | Maps to |
|---|---|---|
| `-d` | Detached mode (daemon-managed background) | `container_args_set_detached(true)` |
| `--name <name>` | Container name (default: use generated ID) | `container_args_set_name()` |
| `--rm` | Auto-remove container on exit | `container_args_set_auto_remove(true)` |
| `--read-only` | Read-only rootfs (no overlay) | `container_args_set_readonly(true)` |
| `-t` | Allocate a pseudo-TTY | `container_args_set_terminal_mode(true)` |
| `-e KEY=VALUE` | Set environment variable (repeatable) | `container_args_add_env()` |
| `-v src:dst[:ro]` | Bind mount (repeatable) | `container_args_add_bind_mount()` |
| `--tmpfs dst[:size]` | tmpfs mount (repeatable, size in bytes, default reasonable) | `container_args_add_tmpfs_mount()` |
| `-p hostPort:containerPort[/tcp\|udp]` | Port forwarding (repeatable, default tcp) | `container_args_add_port_forwarding()` |
| `--network <name>` | Join named NAT network (default: `tcr_default`) | `container_args_set_nat_network(name)` |
| `--no-network` | No network (skip NAT network setup) | skip `container_args_set_nat_network()` |
| `--restart <policy>` | Restart policy: `no`, `unless-stopped`, `always` (default: `no`) | `container_args_set_restart_policy()` |
| `--stop-timeout <sec>` | Graceful stop timeout in seconds (default: 10) | `container_args_set_stop_timeout()` |

#### Image reference

The `<image>` positional argument is resolved via `image_manager_find_by_id_or_name()`:
1. Try as an image id
2. If not found, parse as `name:tag` (default tag: `latest`), try by name

#### Response

- **Interactive** (default): `{ "execArgs": ["crun", "run", ...] }` — client exec's into crun
- **Detached** (`-d`): `{ "exitCode": 0, "stdOut": "<container_id>\n" }` — returns container ID

#### Examples

```bash
tcr run alpine /bin/sh                     # interactive shell, default network
tcr run -d --name web -p 8080:80 nginx     # detached, port forward, default network
tcr run --no-network --read-only alpine cat /etc/os-release
tcr run -d --restart always --name db -v /data/pg:/var/lib/postgresql postgres
```

### `tcr ps`

List all containers.

#### Response

Output table with columns: `ID`, `NAME`, `IMAGE`, `STATUS`, `CREATED`

Status is one of: `running`, `stopped`.

```
ID               NAME    IMAGE                            STATUS
a1b2c3d4e5f6g7h8 web     docker.io/library/nginx:latest   running
f8e7d6c5b4a39281 myapp   docker.io/library/alpine:latest  stopped
```

### `tcr stop <name_or_id>`

Graceful stop. Sends SIGTERM, waits for the stop timeout, then SIGKILL.

Maps to `container_stop(c, false)`.

Returns `{ "exitCode": 0, "stdOut": "<id>\n" }` on success.

### `tcr kill <name_or_id>`

Immediate stop. Sends SIGKILL and waits synchronously.

Maps to `container_stop(c, true)`.

Returns `{ "exitCode": 0, "stdOut": "<id>\n" }` on success.

### `tcr rm <name_or_id>`

Remove a container. Force-stops if still running.

Maps to `container_remove(c)`.

Returns `{ "exitCode": 0, "stdOut": "<id>\n" }` on success.

### `tcr exec [options] <container> <command...>`

Execute a command inside a running container. The daemon builds the `crun exec` argv and returns it as `execArgs`; the client `execvp`'s into crun.

#### Options

| Flag | Description |
|---|---|
| `-d` | Detach — run the command in the background inside the container |
| `-t` | Allocate a pseudo-TTY |
| `-e KEY=VALUE` | Set environment variable (repeatable) |

#### Response

`{ "execArgs": ["crun", "exec", ...] }` — client exec's into crun exec.

#### Errors

- Container not found → error code 2
- Container not running → error code 6
- No command specified → error code 6

#### Examples

```bash
tcr exec mycontainer /bin/sh                  # interactive shell
tcr exec -t mycontainer /bin/bash             # interactive with TTY
tcr exec -d mycontainer top                   # run in background
tcr exec -e MY_VAR=hello mycontainer env      # with env variable
```

---

## Image Commands

### `tcr image load <path>`

Load a squashfs image from the given path. Relative paths are resolved against the client's `pwd`.

Maps to `image_manager_load(mgr, resolved_path)`.

Returns `{ "exitCode": 0, "stdOut": "<id>\n" }` on success.

### `tcr image ls`

List all loaded images.

Output table with columns: `IMAGE ID`, `NAME`, `TAG`, `ARCH`, `MOUNTED`

```
IMAGE ID         NAME                          TAG     ARCH   MOUNTED
a1b2c3d4e5f6g7h8 docker.io/library/alpine      latest  amd64  yes
f8e7d6c5b4a39281 docker.io/library/nginx       1.25    arm64  yes
```

### `tcr image rm <ref>`

Remove an image. `<ref>` can be an image id or `name:tag`. The id is tried first, then name:tag.

Fails if any container is using the image (`container_manager_get_image_ref_count() > 0`).

Maps to `image_manager_remove(mgr, img)`.

Returns `{ "exitCode": 0, "stdOut": "<id>\n" }` on success.

---

## Network Commands

### `tcr network ls`

List all NAT networks.

Maps to `nat_network_manager_foreach_safe()`.

Output table with columns: `NAME`, `SUBNET`, `GATEWAY`

```
NAME         SUBNET        GATEWAY
tcr_default  10.88.0.0/24  10.88.0.1
custom_net   10.89.0.0/24  10.89.0.1
```

### `tcr network rm <name>`

Remove a NAT network. Fails if any container is using the network (`container_manager_get_network_ref_count() > 0`).

Maps to `nat_network_remove_network(mgr, name)`.

Returns `{ "exitCode": 0, "stdOut": "<name>\n" }` on success.

---

## Help

### `tcr help`

Returns usage text listing all available commands and their synopsis. Generated by the daemon so the client never needs updating when commands change.

---

## Error Handling

All errors use the RPC error response format:

```json
{ "error": { "code": <int>, "message": "<string>" } }
```

The client prints `Error (<code>): <message>` to stderr and exits 1.

### Error codes

| Code | Meaning |
|---|---|
| 1 | Unknown command / bad syntax |
| 2 | Container not found |
| 3 | Image not found |
| 4 | Network not found |
| 5 | Resource in use (image has containers, network has containers) |
| 6 | Invalid argument |
| 7 | Internal error |

---

## RPC Method Routing

The daemon maps `method` (argv[1]) to a handler. Subcommands like `image` use the first element of `args` as the sub-verb:

| `method` | `args[0]` | Handler |
|---|---|---|
| `run` | — | `handle_run(args)` |
| `exec` | — | `handle_exec(args)` |
| `ps` | — | `handle_ps(args)` |
| `stop` | — | `handle_stop(args)` |
| `kill` | — | `handle_kill(args)` |
| `rm` | — | `handle_rm(args)` |
| `image` | `load` | `handle_image_load(args+1)` |
| `image` | `ls` | `handle_image_ls(args+1)` |
| `image` | `rm` | `handle_image_rm(args+1)` |
| `network` | `ls` | `handle_network_ls(args+1)` |
| `network` | `rm` | `handle_network_rm(args+1)` |
| `help` | — | `handle_help()` |

Unknown methods return error code 1.

---

## Default Networking Behavior

Every container is attached to a NAT network by default:

- No network flag → join `tcr_default` (created on first use)
- `--network <name>` → join the named network (created on first use)
- `--no-network` → no network namespace, no bridge, no DNS

This means containers can reach the internet and discover each other by name (via the built-in DNS forwarder) out of the box.

---

## Future Commands (Not Yet Implemented)

The following commands are planned but have no implementation yet. They are documented here for design continuity.

### `tcr logs <container>`

Retrieve stdout/stderr output from a detached container.

Requires: changing detached container stdio from `/dev/null` to a log file or ring buffer managed by the daemon. Design choices to make:
- File-based logs vs. in-memory ring buffer
- Log rotation / size limits (important for embedded devices with limited storage)
- Live follow mode (`tcr logs -f`)
