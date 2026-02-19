#!/usr/bin/env bash
set -euo pipefail

# run_test_tcrd.sh — Integration test for tcrd daemon and tcr client.
#
# Starts tcrd under valgrind with a test socket path, then exercises
# all supported commands via the tcr client. Shuts down with SIGTERM
# and checks valgrind output.
#
# Must be run as root (mount, overlay, netns, nftables, crun).
#
# Usage: sudo ./run_test_tcrd.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
CREATE_IMAGE="$SCRIPT_DIR/../host_tools/tcr-create-image.sh"
WORK_DIR="$BUILD_DIR/test_tcrd_work"
IMAGE_REF="docker.io/library/alpine:latest"
SQFS_FILE="$WORK_DIR/alpine_latest.sqfs"
VALGRIND_LOG="$BUILD_DIR/valgrind_tcrd.log"
DATA_DIR="$SCRIPT_DIR/data"
TCR_ROOT="$DATA_DIR/tcr-test-tcrd"

TCRD="$BUILD_DIR/test_tcrd_helper"
TCR="$BUILD_DIR/test_tcr_helper"

TCRD_PID=""

# ── Counters ─────────────────────────────────────────────────────────────────

PASS=0
FAIL=0

pass() {
    PASS=$((PASS + 1))
    echo "  PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1" >&2
}

# Assert that the exit code of the last command matches expected.
# Usage: run_tcr <expected_exit> <description> [args...]
run_tcr() {
    local expected_exit="$1"; shift
    local desc="$1"; shift
    local exit_code=0
    local output
    output=$("$TCR" "$@" 2>&1) || exit_code=$?
    if [[ "$exit_code" -eq "$expected_exit" ]]; then
        pass "$desc (exit=$exit_code)"
    else
        fail "$desc: expected exit=$expected_exit, got exit=$exit_code"
        echo "    output: $output"
    fi
    # Store output for further checks
    LAST_OUTPUT="$output"
}

# Assert output contains a substring
assert_contains() {
    local desc="$1"
    local needle="$2"
    if echo "$LAST_OUTPUT" | grep -qF -- "$needle"; then
        pass "$desc"
    else
        fail "$desc: output does not contain '$needle'"
        echo "    output: $LAST_OUTPUT"
    fi
}

# Assert output does NOT contain a substring
assert_not_contains() {
    local desc="$1"
    local needle="$2"
    if echo "$LAST_OUTPUT" | grep -qF -- "$needle"; then
        fail "$desc: output unexpectedly contains '$needle'"
        echo "    output: $LAST_OUTPUT"
    else
        pass "$desc"
    fi
}

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

if [[ ! -x "$TCRD" ]]; then
    echo "error: test_tcrd_helper not found — build it first" >&2
    echo "  cd test/build && cmake .. && make test_tcrd_helper test_tcr_helper" >&2
    exit 1
fi

if [[ ! -x "$TCR" ]]; then
    echo "error: test_tcr_helper not found — build it first" >&2
    exit 1
fi

if ! command -v valgrind &>/dev/null; then
    echo "error: valgrind not found" >&2
    exit 1
fi

if ! command -v crun &>/dev/null; then
    echo "error: crun not found" >&2
    exit 1
fi

# ── Cleanup function ────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "=== Cleaning up ==="

    # Stop tcrd if still running
    if [[ -n "$TCRD_PID" ]] && kill -0 "$TCRD_PID" 2>/dev/null; then
        echo "  Killing leftover tcrd (pid=$TCRD_PID)"
        kill -9 "$TCRD_PID" 2>/dev/null || true
        wait "$TCRD_PID" 2>/dev/null || true
    fi

    # Unmount any leftover mounts
    mount | grep "$TCR_ROOT" | awk '{print $3}' | sort -r | while read -r mp; do
        umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
    done || true

    # Clean up network namespaces
    for ns in /var/run/netns/tcr-*; do
        if [[ -e "$ns" ]]; then
            ip netns del "$(basename "$ns")" 2>/dev/null || true
        fi
    done

    rm -rf "$TCR_ROOT"
}
trap cleanup EXIT

# ── Prepare the test image ──────────────────────────────────────────────────

mkdir -p "$DATA_DIR" "$WORK_DIR"

if [[ -f "$SQFS_FILE" ]]; then
    echo "=== Using existing test image: $SQFS_FILE ==="
else
    echo "=== Creating test image from $IMAGE_REF ==="
    bash "$CREATE_IMAGE" -o "$SQFS_FILE" -w "$WORK_DIR/tcr-build" -f "$IMAGE_REF"
    echo ""
fi

if [[ ! -f "$SQFS_FILE" ]]; then
    echo "error: failed to create test image" >&2
    exit 1
fi

# ── Ensure clean state ──────────────────────────────────────────────────────

rm -rf "$TCR_ROOT"

# ── Start tcrd under valgrind ────────────────────────────────────────────────

echo "=== Starting tcrd under valgrind ==="
echo "    root: $TCR_ROOT"
echo "    log:  $VALGRIND_LOG"
echo ""

valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --errors-for-leak-kinds=definite \
    --track-origins=yes \
    --trace-children=no \
    --child-silent-after-fork=yes \
    --error-exitcode=99 \
    --log-file="$VALGRIND_LOG" \
    "$TCRD" --root "$TCR_ROOT" &
TCRD_PID=$!

# Wait for daemon to be ready (it creates the socket quickly, but
# under valgrind it's slower — poll for connectivity)
echo "  Waiting for tcrd to be ready..."
READY=0
for i in $(seq 1 30); do
    if "$TCR" help >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.5
done

if [[ "$READY" -ne 1 ]]; then
    echo "error: tcrd did not become ready within 15 seconds" >&2
    kill -9 "$TCRD_PID" 2>/dev/null || true
    exit 1
fi

echo "  tcrd ready (pid=$TCRD_PID)"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
#  Tests
# ═════════════════════════════════════════════════════════════════════════════

echo "=== Running tests ==="
echo ""

# ── help ─────────────────────────────────────────────────────────────────────

echo "--- help ---"
run_tcr 0 "help command" help
assert_contains "help lists run command" "run [options]"
assert_contains "help lists image commands" "image load"
assert_contains "help lists network commands" "network ls"
echo ""

# ── unknown command ──────────────────────────────────────────────────────────

echo "--- unknown command ---"
run_tcr 1 "unknown command returns error" foobar
assert_contains "unknown command error message" "unknown command"
echo ""

# ── image load ───────────────────────────────────────────────────────────────

echo "--- image load ---"
run_tcr 0 "image load" image load "$SQFS_FILE"
IMAGE_ID=$(echo "$LAST_OUTPUT" | tr -d '[:space:]')
assert_contains "image load returns id" "$IMAGE_ID"
echo "  loaded: $IMAGE_ID"
echo ""

# ── image ls ─────────────────────────────────────────────────────────────────

echo "--- image ls ---"
run_tcr 0 "image ls" image ls
assert_contains "image ls shows alpine" "alpine"
assert_contains "image ls header" "IMAGE ID"
echo ""

# ── image load duplicate ─────────────────────────────────────────────────────

echo "--- image load duplicate ---"
run_tcr 1 "image load duplicate fails" image load "$SQFS_FILE"
echo ""

# ── run (detached, read-only, no-network) ────────────────────────────────────

echo "--- run detached container ---"
run_tcr 0 "run detached readonly no-network" \
    run -d --name test1 --read-only --no-network alpine cat /etc/os-release
CONTAINER_ID=$(echo "$LAST_OUTPUT" | tr -d '[:space:]')
echo "  container: $CONTAINER_ID"
echo ""

# Give the container a moment to run and exit
sleep 2

# ── ps ───────────────────────────────────────────────────────────────────────

echo "--- ps ---"
run_tcr 0 "ps" ps
assert_contains "ps shows container" "test1"
assert_contains "ps header" "ID"
echo ""

# ── run (detached, with network) ─────────────────────────────────────────────

echo "--- run detached with default network ---"
run_tcr 0 "run detached with network" \
    run -d --name test2 alpine sleep 300
CONTAINER_ID2=$(echo "$LAST_OUTPUT" | tr -d '[:space:]')
echo "  container: $CONTAINER_ID2"
echo ""

# Give the container a moment to start
sleep 3

# ── ps (should show running container) ───────────────────────────────────────

echo "--- ps (running containers) ---"
run_tcr 0 "ps shows running" ps
assert_contains "ps shows test2" "test2"
echo ""

# ── network ls ───────────────────────────────────────────────────────────────

echo "--- network ls ---"
run_tcr 0 "network ls" network ls
assert_contains "network ls header" "NAME"
assert_contains "network ls shows tcr_default" "tcr_default"
echo ""

# ── exec (while test2 is running) ───────────────────────────────────────────

echo "--- exec ---"

# exec a simple command — the client execvp's into crun, so we get the
# actual command output (not the raw execArgs).
run_tcr 0 "exec cat in running container" exec test2 cat /etc/os-release
assert_contains "exec output has alpine" "Alpine"
echo ""

# exec with -e env
run_tcr 0 "exec with -e" exec -e MY_VAR=hello test2 /bin/sh -c 'echo $MY_VAR'
assert_contains "exec -e value" "hello"
echo ""

# exec non-existent container
run_tcr 1 "exec nonexistent container" exec nonexistent_ctr cat /etc/os-release
assert_contains "exec nonexistent error" "not found"
echo ""

# exec no command
run_tcr 1 "exec no command" exec test2
assert_contains "exec no command error" "no command"
echo ""

# exec unknown flag
run_tcr 1 "exec unknown flag" exec --bogus test2 sh
assert_contains "exec unknown flag error" "unknown option"
echo ""

# exec bad -e format
run_tcr 1 "exec bad -e" exec -e BADENV test2 sh
assert_contains "exec bad env error" "KEY=VALUE"
echo ""

# ── stop ─────────────────────────────────────────────────────────────────────

echo "--- stop ---"
run_tcr 0 "stop test2" kill test2
assert_contains "stop returns container id" "$CONTAINER_ID2"
echo ""

sleep 2

echo "--- ps after stop ---"
run_tcr 0 "ps after stop" ps
assert_contains "ps shows stopped" "stopped"
echo ""

# ── exec on stopped container ────────────────────────────────────────────────

echo "--- exec on stopped container ---"
run_tcr 1 "exec on stopped container" exec test2 echo test
assert_contains "exec stopped error" "not running"
echo ""

# ── stop non-existent ────────────────────────────────────────────────────────

echo "--- stop non-existent ---"
run_tcr 1 "stop nonexistent" stop nonexistent_container
assert_contains "stop error message" "not found"
echo ""

# ── rm ───────────────────────────────────────────────────────────────────────

echo "--- rm ---"
run_tcr 0 "rm test1" rm test1
echo ""

run_tcr 0 "rm test2" rm test2
echo ""

echo "--- ps after rm ---"
run_tcr 0 "ps after rm (empty)" ps
assert_not_contains "ps empty of test1" "test1"
assert_not_contains "ps empty of test2" "test2"
echo ""

# ── rm non-existent ──────────────────────────────────────────────────────────

echo "--- rm non-existent ---"
run_tcr 1 "rm nonexistent" rm nonexistent_container
assert_contains "rm error message" "not found"
echo ""

# ── run with options (detached, env, tmpfs) ──────────────────────────────────

echo "--- run with env and tmpfs ---"
run_tcr 0 "run with env and tmpfs" \
    run -d --name test3 --rm --no-network \
    -e MY_VAR=hello --tmpfs /tmp:67108864 \
    alpine sleep 1
CONTAINER_ID3=$(echo "$LAST_OUTPUT" | tr -d '[:space:]')
echo "  container: $CONTAINER_ID3"
echo ""

# Wait for it to exit + auto-remove
sleep 4

echo "--- auto-remove check ---"
run_tcr 0 "ps after auto-remove" ps
assert_not_contains "auto-removed container gone" "test3"
echo ""

# ── run --config (detached, read-only, no-network) ──────────────────────────

echo "--- run --config (basic) ---"

CONFIG_FILE="$WORK_DIR/test_config.json"
cat > "$CONFIG_FILE" <<EOF
{
  "image": "alpine",
  "name": "config_test1",
  "detached": true,
  "readonly": true,
  "noNetwork": true,
  "command": ["cat", "/etc/os-release"]
}
EOF

run_tcr 0 "run --config basic" run --config "$CONFIG_FILE"
CONFIG_CTR_ID=$(echo "$LAST_OUTPUT" | tr -d '[:space:]')
echo "  container: $CONFIG_CTR_ID"

sleep 2

run_tcr 0 "ps shows config container" ps
assert_contains "ps shows config_test1" "config_test1"
echo ""

# ── run --config (with network and env) ──────────────────────────────────────

echo "--- run --config (with network and env) ---"

CONFIG_FILE2="$WORK_DIR/test_config2.json"
cat > "$CONFIG_FILE2" <<EOF
{
  "image": "alpine",
  "name": "config_test2",
  "detached": true,
  "env": { "MY_VAR": "from_config" },
  "command": ["sleep", "300"]
}
EOF

run_tcr 0 "run --config with network" run --config "$CONFIG_FILE2"
CONFIG_CTR_ID2=$(echo "$LAST_OUTPUT" | tr -d '[:space:]')
echo "  container: $CONFIG_CTR_ID2"

sleep 3

# exec to verify env var was set from config
run_tcr 0 "exec env from config" exec config_test2 /bin/sh -c 'echo $MY_VAR'
assert_contains "env from config value" "from_config"
echo ""

# ── run --config (error: conflicting network/noNetwork) ──────────────────────

echo "--- run --config (error cases) ---"

CONFIG_BAD="$WORK_DIR/test_config_bad.json"
cat > "$CONFIG_BAD" <<EOF
{
  "image": "alpine",
  "network": "mynet",
  "noNetwork": true
}
EOF

run_tcr 1 "run --config network conflict" run --config "$CONFIG_BAD"
assert_contains "config conflict error" "mutually exclusive"

# --config with extra args should fail
run_tcr 1 "run --config with extra args" run --config "$CONFIG_FILE" -d
assert_contains "config extra args error" "cannot be combined"

# --config with missing file
run_tcr 1 "run --config missing file" run --config /tmp/does_not_exist_tcr.json
assert_contains "config missing file error" "failed to load"

# --config with invalid JSON
INVALID_JSON="$WORK_DIR/test_config_invalid.json"
echo "{ not valid json }" > "$INVALID_JSON"
run_tcr 1 "run --config invalid json" run --config "$INVALID_JSON"
echo ""

# ── Cleanup config test containers ──────────────────────────────────────────

echo "--- cleanup config test containers ---"
run_tcr 0 "kill config_test2" kill config_test2

sleep 2

run_tcr 0 "rm config_test1" rm config_test1
run_tcr 0 "rm config_test2" rm config_test2
echo ""

# ── image rm (no containers referencing it) ──────────────────────────────────

echo "--- image rm ---"
run_tcr 0 "image rm" image rm alpine:latest
assert_contains "image rm returns id" "$IMAGE_ID"
echo ""

# ── image ls (should be empty) ───────────────────────────────────────────────

echo "--- image ls after rm ---"
run_tcr 0 "image ls after rm" image ls
assert_not_contains "no alpine in list" "alpine"
echo ""

# ── image rm non-existent ────────────────────────────────────────────────────

echo "--- image rm non-existent ---"
run_tcr 1 "image rm nonexistent" image rm nonexistent:latest
assert_contains "image rm error" "not found"
echo ""

# ── network rm (no containers using it) ──────────────────────────────────────

echo "--- network rm ---"
run_tcr 0 "network rm tcr_default" network rm tcr_default
echo ""

echo "--- network ls after rm ---"
run_tcr 0 "network ls empty" network ls
assert_not_contains "tcr_default removed" "tcr_default"
echo ""

# ── network rm non-existent ──────────────────────────────────────────────────

echo "--- network rm non-existent ---"
run_tcr 1 "network rm nonexistent" network rm nonexistent_net
assert_contains "network rm error" "not found"
echo ""

# ── bad run args ─────────────────────────────────────────────────────────────

echo "--- bad run args ---"
run_tcr 1 "run no image" run -d
assert_contains "run no image error" "no image"

run_tcr 1 "run unknown flag" run --bogus alpine
assert_contains "run unknown flag error" "unknown option"

run_tcr 1 "run bad -e" run -d -e BADENV alpine
assert_contains "run bad env error" "KEY=VALUE"

run_tcr 1 "run bad -p" run -d -p badport alpine
assert_contains "run bad port error" "-p format"
echo ""

# ── bad image subcommand ─────────────────────────────────────────────────────

echo "--- bad image subcommand ---"
run_tcr 1 "image unknown sub" image badcmd
assert_contains "image bad sub error" "unknown image subcommand"
echo ""

# ── bad network subcommand ───────────────────────────────────────────────────

echo "--- bad network subcommand ---"
run_tcr 1 "network unknown sub" network badcmd
assert_contains "network bad sub error" "unknown network subcommand"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
#  Shutdown
# ═════════════════════════════════════════════════════════════════════════════

echo "=== Shutting down tcrd (SIGTERM) ==="
kill -15 "$TCRD_PID"

# Wait for valgrind+tcrd to exit
WAIT_EXIT=0
wait "$TCRD_PID" || WAIT_EXIT=$?
TCRD_PID=""
echo "  tcrd exited (code=$WAIT_EXIT)"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
#  Valgrind report
# ═════════════════════════════════════════════════════════════════════════════

echo "=== Valgrind summary ==="
# Show only the main tcrd process summary (filter by its PID)
VG_PID=$(head -1 "$VALGRIND_LOG" | grep -oP '==\K[0-9]+')
grep "==$VG_PID==" "$VALGRIND_LOG" | tail -20
echo ""

# ═════════════════════════════════════════════════════════════════════════════
#  Results
# ═════════════════════════════════════════════════════════════════════════════

echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [[ "$WAIT_EXIT" -eq 99 ]]; then
    echo "FAIL: valgrind detected memory errors (see $VALGRIND_LOG)"
    FAIL=$((FAIL + 1))
fi

if [[ "$FAIL" -gt 0 ]]; then
    echo "FAIL: $FAIL test(s) failed"
    exit 1
else
    echo "PASS: all $PASS assertions passed, tcrd clean shutdown"
fi
