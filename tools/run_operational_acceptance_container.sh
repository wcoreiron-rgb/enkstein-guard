#!/bin/sh
# Run every operational-acceptance group inside one candidate Linux container
# (no network, read-only root, non-root UID, shared tmpfs state). Results merge
# into one report in .local-deploy/operational/. The tag is resolved to an image
# ID once; the container runs that ID, and the report embeds the image identity
# probe and the Docker engine (tools/evidence.py image).
# Usage: tools/run_operational_acceptance_container.sh <host python> [tag]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${1:?python}
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$ROOT/src/enkstein_guard/__init__.py")
TAG=${2:-enkstein-guard:$VERSION}
OUT="$ROOT/.local-deploy/operational"
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$TAG") || exit 10
rm -rf "$OUT" && mkdir -p "$OUT" && chmod 0777 "$OUT"
"$PYTHON" "$ROOT/tools/evidence.py" image "$IMAGE_ID" > "$OUT/image.json" || exit 11
chmod 0644 "$OUT/image.json"
echo "image_id=$IMAGE_ID"
docker run --rm --user 10001:10001 --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,size=1536m \
  -e ENKSTEIN_POLICY_PACK=/nonexistent -e GUARD_IMAGE_INFO=/out/image.json \
  -v "$ROOT":/project:ro -v "$OUT":/out \
  --entrypoint sh "$IMAGE_ID" -c '
    nproc > /out/nproc.txt; grep MemTotal /proc/meminfo >> /out/nproc.txt
    status=0
    for group in sustained burst vault state; do
      python /project/tools/operational_acceptance.py --group "$group" --work /tmp/oa \
        --output /out/operational-acceptance.json --duration 300 || status=1
    done
    echo "operational_acceptance_status=$status"
    exit $status'
status=$?
# The report is copied even after a failure (it records which targets were not
# met or not run); the exit status says whether every group completed.
mkdir -p "$ROOT/verification/$VERSION/configurations"
cp "$OUT/operational-acceptance.json" "$ROOT/verification/$VERSION/operational-acceptance-container.json" || status=1
cp "$OUT/configurations/operational-acceptance-container.guard.json" "$ROOT/verification/$VERSION/configurations/" || status=1
exit $status
