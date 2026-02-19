#!/bin/bash
set -euo pipefail

# tcr-create-image — Pull an OCI image, unpack it, and package it as a
# squashfs file ready for use with tcr.
#
# Dependencies: skopeo, umoci, mksquashfs (squashfs-tools), jq

readonly PROG="$(basename "$0")"

# ── Helpers ──────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $PROG [OPTIONS] <image>

Pull an OCI container image, unpack it, and package it into a squashfs file.

Arguments:
  <image>    OCI image reference (e.g. docker.io/library/alpine:latest)

Options:
  -o, --output <path>    Output .sqfs file path (default: ./<name>.sqfs)
  -w, --working <dir>    Working/build directory (default: ./tcr-build)
  -f, --force            Overwrite existing output file and build directory
                         without prompting
  -h, --help             Show this help message and exit

Examples:
  $PROG docker.io/library/alpine:latest
  $PROG -o images/alpine.sqfs alpine:latest
  $PROG -w /tmp/tcr-build -o out.sqfs myregistry.io/app:v2
EOF
    exit "${1:-0}"
}

die() { echo "error: $*" >&2; exit 1; }

check_deps() {
    local missing=()
    for cmd in skopeo umoci mksquashfs jq xxhsum; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "missing required dependencies: ${missing[*]}"
    fi
}

# Sanitize an image reference into a safe filename component.
# docker.io/library/alpine:latest -> alpine_latest
sanitize_name() {
    echo "$1" | sed 's|.*/||; s/:/_/g; s/[^a-zA-Z0-9_.-]/_/g'
}

# Normalize an image reference into registry, repository, and tag.
# Handles shorthand forms:
#   alpine            -> docker.io  library/alpine  latest
#   alpine:3.18       -> docker.io  library/alpine  3.18
#   myuser/app:v1     -> docker.io  myuser/app      v1
#   ghcr.io/o/img:v1  -> ghcr.io   o/img           v1
# Sets: REGISTRY, REPO, TAG
parse_image_ref() {
    local ref="$1"

    # Extract tag (after last colon, but not if colon is in a port like localhost:5000)
    if [[ "$ref" =~ :([^:/]+)$ ]]; then
        TAG="${BASH_REMATCH[1]}"
        ref="${ref%:$TAG}"
    else
        TAG="latest"
    fi

    # Split on slashes
    local slash_count
    slash_count=$(echo "$ref" | tr -cd '/' | wc -c)

    if [[ $slash_count -eq 0 ]]; then
        # bare name: alpine
        REGISTRY="docker.io"
        REPO="library/$ref"
    elif [[ $slash_count -eq 1 ]]; then
        local first="${ref%%/*}"
        # A registry hostname contains a dot or a colon (port).
        # Otherwise it's a Docker Hub user/org.
        if [[ "$first" == *"."* || "$first" == *":"* ]]; then
            REGISTRY="$first"
            REPO="${ref#*/}"
        else
            REGISTRY="docker.io"
            REPO="$ref"
        fi
    else
        # two or more slashes: first component is registry
        REGISTRY="${ref%%/*}"
        REPO="${ref#*/}"
    fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────

OUTPUT=""
WORK_DIR=""
FORCE=0
IMAGE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)    usage 0 ;;
        -o|--output)  [[ -n "${2:-}" ]] || die "option $1 requires an argument"; OUTPUT="$2"; shift 2 ;;
        -w|--working) [[ -n "${2:-}" ]] || die "option $1 requires an argument"; WORK_DIR="$2"; shift 2 ;;
        -f|--force)   FORCE=1; shift ;;
        -*)           die "unknown option: $1 (see --help)" ;;
        *)
            [[ -z "$IMAGE" ]] || die "unexpected argument: $1 (image already set to '$IMAGE')"
            IMAGE="$1"; shift ;;
    esac
done

[[ -n "$IMAGE" ]] || { echo "error: <image> argument is required" >&2; usage 1; }

# ── Dependency check ────────────────────────────────────────────────────────

check_deps

# ── Derived variables ────────────────────────────────────────────────────────

SANITIZED_NAME="$(sanitize_name "$IMAGE")"
parse_image_ref "$IMAGE"

WORK_DIR="${WORK_DIR:-$PWD/tcr-build}"
SQFS_FILE="${OUTPUT:-$PWD/${SANITIZED_NAME}.sqfs}"

# Resolve to absolute paths
WORK_DIR="$(mkdir -p "$WORK_DIR" && cd "$WORK_DIR" && pwd)"
SQFS_FILE="$(cd "$(dirname "$SQFS_FILE")" 2>/dev/null && pwd)/$(basename "$SQFS_FILE")"

OCI_DIR="$WORK_DIR/oci-image"
STAGE_DIR="$WORK_DIR/stage"
BUNDLE_DIR="$STAGE_DIR/bundle"

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ -e "$SQFS_FILE" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
        rm -f "$SQFS_FILE"
    else
        die "output file already exists: $SQFS_FILE (use -f to overwrite)"
    fi
fi

if [[ -d "$WORK_DIR" && "$(ls -A "$WORK_DIR" 2>/dev/null)" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
        echo "==> Cleaning previous build directory..."
        sudo rm -rf "$WORK_DIR"
        mkdir -p "$WORK_DIR"
    else
        die "build directory is not empty: $WORK_DIR (use -f to overwrite)"
    fi
fi

mkdir -p "$WORK_DIR" "$STAGE_DIR"

# ── Cleanup trap ─────────────────────────────────────────────────────────────

BUILD_OK=0
cleanup() {
    if [[ -d "$WORK_DIR" ]]; then
        [[ "$BUILD_OK" -eq 0 ]] && echo "==> Build failed. Cleaning up..." >&2 \
                                 || echo "==> Cleaning up build directory..."
        rm -rf "$WORK_DIR" 2>/dev/null || sudo rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

# ── Summary ──────────────────────────────────────────────────────────────────

echo "==> Image:   $IMAGE"
echo "==> Output:  $SQFS_FILE"
echo "==> WorkDir: $WORK_DIR"
echo ""

# ── Step 1: Pull image to OCI layout ────────────────────────────────────────

echo "==> Pulling image to OCI layout..."
skopeo copy "docker://$IMAGE" "oci:$OCI_DIR:$TAG"

# Get image digest and arch for metadata
DIGEST=$(skopeo inspect "oci:$OCI_DIR:$TAG" | jq -r '.Digest // "unknown"')
ARCH=$(skopeo inspect "oci:$OCI_DIR:$TAG" | jq -r '.Architecture // "unknown"')

# Compute image ID: 64-bit xxHash of the digest, as a hex string
IMAGE_ID=$(echo -n "$DIGEST" | xxhsum -H64 | cut -d' ' -f1)

# ── Step 2: Unpack to bundle ────────────────────────────────────────────────

echo "==> Unpacking OCI image to bundle..."
sudo umoci unpack --image "$OCI_DIR:$TAG" "$BUNDLE_DIR"

# ── Step 3: Generate image-info.json ─────────────────────────────────────────

echo "==> Generating image-info.json..."
cat > "$STAGE_DIR/image-info.json" <<EOF
{
    "version": 1,
    "image": {
        "id": "$IMAGE_ID",
        "registry": "$REGISTRY",
        "repository": "$REPO",
        "tag": "$TAG",
        "digest": "$DIGEST",
        "arch": "$ARCH"
    },
    "bundlePath": "bundle",
    "created": $(date +%s)
}
EOF

echo "==> image-info.json:"
cat "$STAGE_DIR/image-info.json"

# ── Step 4: Package into squashfs ────────────────────────────────────────────

echo "==> Creating squashfs image..."
sudo mksquashfs "$STAGE_DIR" "$SQFS_FILE" -noappend -comp zstd -quiet
sudo chown "$(id -u):$(id -g)" "$SQFS_FILE"

BUILD_OK=1

echo ""
echo "==> Done! Image written to: $SQFS_FILE"
ls -lh "$SQFS_FILE"
