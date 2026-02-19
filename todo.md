# TCR — TODO

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
