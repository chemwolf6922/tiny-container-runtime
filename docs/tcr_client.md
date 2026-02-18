# TCR Client Design

## Purpose

The `tcr` binary is a thin CLI client that acts as a pass-through channel between the user and the `tcrd` daemon. It contains **no business logic** — it simply forwards the user's command to the daemon via JSON RPC over a Unix domain socket and handles the response.

## Architecture

```
User                       tcr (client)                          tcrd (daemon)
  │                            │                                      │
  ├─ tcr run --name foo ──────▶│                                      │
  │                            ├─ connect(@tiny_container_runtime) ──▶│
  │                            ├─ {"method":"run", "params":{...}} ──▶│
  │                            │                                      ├─ process
  │                            │◀── {"result": {exitCode,stdOut,...}} ─┤
  │◀── stdout/stderr + exit ───┤                                      │
```

The client uses `SOCK_SEQPACKET` Unix domain sockets in the Linux abstract namespace (`@tiny_container_runtime`). Communication is fully asynchronous via the tev event loop.

## RPC Protocol

### Request

The client maps `argv` directly to a JSON RPC request:

```
tcr <method> [arg1] [arg2] ...
     argv[1]  argv[2:]
```

```json
{
  "id": 1,
  "method": "run",
  "params": {
    "args": ["--name", "foo", "-d", "alpine"],
    "pwd": "/home/user/project",
    "pid": 12345
  }
}
```

| Field | Source |
|-------|--------|
| `method` | `argv[1]` |
| `params.args` | `argv[2:]` (may be empty) |
| `params.pwd` | Client's current working directory (`getcwd`) |
| `params.pid` | Client's process ID (`getpid`) |

### Response Format 1: Output + Exit Code

For commands that produce output and complete:

```json
{
  "id": 1,
  "result": {
    "exitCode": 0,
    "stdOut": "container created\n",
    "stdErr": ""
  }
}
```

Client behavior:
1. Write `stdOut` to stdout (if non-empty)
2. Write `stdErr` to stderr (if non-empty)
3. Exit with `exitCode`

### Response Format 2: Exec

For commands that require the client to replace itself (e.g. interactive container exec):

```json
{
  "id": 1,
  "result": {
    "execArgs": ["/usr/bin/crun", "exec", "-t", "mycontainer", "/bin/sh"]
  }
}
```

Client behavior:
1. Close the RPC connection (release the fd)
2. `execvp(execArgs[0], execArgs)` — replace the client process

### Error Response

```json
{
  "id": 1,
  "error": {
    "code": 99,
    "message": "container not found"
  }
}
```

Client behavior:
1. Print `Error (<code>): <message>` to stderr
2. Exit with code 1

Local errors (connection failure, timeout, disconnect) follow the same pattern: print to stderr and exit 1.

## No-Argument Behavior

When invoked with no arguments (`tcr` alone), the client prints a usage hint to stderr and exits 1 without connecting to the daemon:

```
Usage: tcr <command> [args...]
Run 'tcr help' for more information.
```

The `help` command itself is a normal RPC request to the daemon.

## Event Loop Lifecycle

The client uses tev for async I/O. The event loop exits naturally when all fd handlers are removed:

1. **Normal flow**: `on_result` or `on_error` calls `rpc_client_close()` → fd handlers removed → loop exits
2. **Connect failure**: RPC layer releases the client before calling `on_connect_result(false)` → no handlers remain → loop exits
3. **Disconnect/Cancel**: RPC layer cleans up handlers internally → loop exits
4. **Exec path**: `rpc_client_close()` before `execvp()` → process replaced (loop never resumes)

## Key Design Decisions

### Dummy client (no logic)

All command parsing, validation, and execution logic lives in the daemon. The client is intentionally simple — it doesn't know what commands exist or how to process them. This means:
- Adding new commands requires no client changes
- The client binary is small and rarely needs rebuilding
- All state lives in one place (the daemon)

### Abstract namespace socket

Using `@tiny_container_runtime` (Linux abstract namespace) instead of a filesystem socket avoids permission issues, cleanup on crash, and filesystem dependencies.

### Socket path override

`TCR_SOCKET_PATH` is defined in `src/app/common.h` with an `#ifndef` guard, allowing compile-time override for testing:

```c
#ifndef TCR_SOCKET_PATH
#define TCR_SOCKET_PATH "@tiny_container_runtime"
#endif
```

## Build

Production build (Release, from project root):

```bash
mkdir -p build && cd build && cmake .. && make
```

The top-level `CMakeLists.txt` builds the `tcr` binary.
