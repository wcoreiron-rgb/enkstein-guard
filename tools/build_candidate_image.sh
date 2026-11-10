#!/bin/sh
# Build the Alpine ARM64 candidate image from the reviewed wheel and the
# hash-locked musl wheelhouse using a minimal build context.
# Usage: tools/build_candidate_image.sh <wheel path relative to project root> <tag>
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WHEEL=${1:?wheel}
TAG=${2:?tag}
CONTEXT=$(mktemp -d "${TMPDIR:-/tmp}/guard-image-XXXXXX")
trap 'rm -rf "$CONTEXT"' EXIT
mkdir -p "$CONTEXT/deployment" "$CONTEXT/$(dirname "$WHEEL")" "$CONTEXT/dist/vendor-linux-musl-arm64"
cp "$ROOT/deployment/Dockerfile.alpine" "$CONTEXT/deployment/"
cp "$ROOT/$WHEEL" "$CONTEXT/$WHEEL"
cp "$ROOT/dist/vendor-linux-musl-arm64/"* "$CONTEXT/dist/vendor-linux-musl-arm64/"
VERSION=$(basename "$WHEEL" | sed 's/^enkstein_guard-//; s/-py3-none-any.whl$//')
DIGEST=$(shasum -a 256 "$ROOT/$WHEEL" 2>/dev/null || sha256sum "$ROOT/$WHEEL")
grep -q "^enkstein-guard==$VERSION --hash=sha256:${DIGEST%% *}$" "$CONTEXT/dist/vendor-linux-musl-arm64/requirements.txt" \
  || { echo "wheel is not the one in the musl hash lock" >&2; exit 3; }
docker build -f "$CONTEXT/deployment/Dockerfile.alpine" --build-arg "GUARD_WHEEL=$WHEEL" -t "$TAG" "$CONTEXT"
docker image inspect -f '{{.Id}}' "$TAG"
