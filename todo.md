# TCR — TODO

## `tcr exec` — Execute a command inside a running container

**Priority**: High — essential for debugging and interactive use.

### Design

`tcr exec [options] <container> <command...>`

Works like interactive `run`: the daemon builds the `crun exec` argv and returns it as `execArgs`; the client `execvp`'s into crun.

**Planned options**:
- `-t` — allocate a pseudo-TTY
- `-e KEY=VALUE` — pass environment variables (repeatable)

**RPC flow**:
1. Client sends `{ "method": "exec", "params": { "args": ["-t", "<container>", "sh"], "pwd": "...", "pid": ... } }`
2. Daemon validates container exists and is running
3. Daemon builds argv: `["crun", "exec", "-t", "<id>", "<cmd>", ...]`
4. Response: `{ "execArgs": ["crun", "exec", ...] }`
5. Client `execvp`'s into crun

**Implementation tasks**:
- [ ] Add `container_manager_get_exec_args()` API to `container_manager.{c,h}`
  - Validate container is in `RUNNING` state
  - Build crun exec command line with container ID and user command
  - Handle `-t` (TTY) and `-e` (env) options
- [ ] Add `handle_exec()` handler in `tcrd.c`
  - Parse options (`-t`, `-e KEY=VALUE`)
  - Call container_manager API
  - Return `execArgs` response (same format as interactive `run`)
- [ ] Wire into `on_rpc_request()` dispatch
- [ ] Handle in `tcr.c` client — already handled (client execvp's any `execArgs` response)
- [ ] Add tests to `run_test_tcrd.sh`
- [ ] Update `docs/tcr_commands.md` — move from "Future" to main section

---

## `tcr logs` — Retrieve container stdout/stderr

**Priority**: Medium — needed for detached container debugging, but requires infrastructure changes.

### Design

`tcr logs [options] <container>`

Currently detached containers redirect stdio to `/dev/null`. This feature requires capturing output to a log sink.

**Planned options**:
- `-f` / `--follow` — live-stream new output (like `tail -f`)
- `-n <lines>` / `--tail <lines>` — show last N lines (default: all)

### Open design decisions

1. **Log sink**: file-based vs. in-memory ring buffer
   - **File-based**: simpler, survives daemon restart, but embedded devices have limited storage
   - **Ring buffer**: memory-efficient, fixed size, but lost on daemon restart
   - **Recommendation**: file-based with size cap + rotation (e.g. 1MB per container, single file, truncate from head)

2. **Storage location**: `<container_dir>/container.log`

3. **Live follow** (`-f`): daemon sends initial log content, then streams new lines via the RPC connection. Requires either:
   - Keeping the RPC connection open (streaming response) — needs RPC protocol extension
   - Polling with offset — simpler but less real-time

**Implementation tasks**:
- [ ] Decide on log sink approach (file vs. ring buffer)
- [ ] Change detached container stdio: redirect stdout/stderr to log file instead of `/dev/null` in `container_manager.c`
- [ ] Add log file path to container metadata (`meta.json`)
- [ ] Implement `handle_logs()` handler in `tcrd.c`
  - Read log file content
  - Handle `--tail` line limiting
- [ ] Decide on and implement `-f` (follow) mode
- [ ] Add tests
- [ ] Update `docs/tcr_commands.md`
