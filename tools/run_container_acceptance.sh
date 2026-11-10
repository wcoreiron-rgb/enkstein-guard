#!/bin/sh
# Build the candidate image and run the container acceptance checks against it.
# Synthetic data only; each check removes its own Compose project and volumes.
# Long runs (capacity, soak) are separate: deployment/test_production_capacity.py
# and deployment/test_production_soak.py.
# Usage: tools/run_container_acceptance.sh <python with cryptography> [tag]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${1:?python}
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$ROOT/src/enkstein_guard/__init__.py")
TAG=${2:-enkstein-guard:$VERSION}
EVIDENCE="$ROOT/verification/$VERSION"
mkdir -p "$EVIDENCE"
cd "$ROOT"
status=0
sh tools/build_candidate_image.sh "dist/deployment/enkstein_guard-$VERSION-py3-none-any.whl" "$TAG" || exit 10
GUARD_TEST_IMAGE="$TAG" GUARD_EVIDENCE_DIR="$EVIDENCE" "$PYTHON" deployment/test_production_profile.py || status=1
GUARD_TEST_IMAGE="$TAG" GUARD_EVIDENCE_DIR="$EVIDENCE" "$PYTHON" deployment/test_isolation.py > /dev/null || status=1
GUARD_TEST_IMAGE="$TAG" GUARD_EVIDENCE_DIR="$EVIDENCE" "$PYTHON" deployment/test_peer_isolation.py > /dev/null || status=1
GUARD_TEST_IMAGE="$TAG" GUARD_EVIDENCE_DIR="$EVIDENCE" "$PYTHON" deployment/test_production_disk_full.py || status=1
"$PYTHON" tools/scan_image.py --image "$TAG" --refresh-db --output "$EVIDENCE/alpine-os-scan.json" > /dev/null || status=1
echo "container_acceptance_status=$status"
exit $status
