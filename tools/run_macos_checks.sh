#!/bin/sh
# macOS checks against the candidate wheel without modifying existing virtual
# environments. Core and attack suites run in a fresh virtual environment that
# contains only the candidate wheel and the locked dependency versions (macOS
# wheels), so no other copy can shadow it. The optional SDK suite needs the
# existing engines environment; there the wheel is unpacked into a private
# target directory placed first on PYTHONPATH, and the report's dependency
# inventory lists the shadowed copy.
# Usage: tools/run_macos_checks.sh <core python> [optional-engines python]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CORE=${1:?python}
ENGINES=${2:-}
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$ROOT/src/enkstein_guard/__init__.py")
WHEEL="$ROOT/dist/deployment/enkstein_guard-$VERSION-py3-none-any.whl"
EVIDENCE="$ROOT/verification/$VERSION"
VENV="$ROOT/.local-deploy/macos-candidate-venv"
SITE="$ROOT/.local-deploy/candidate-site"
mkdir -p "$EVIDENCE"
rm -rf "$VENV" "$SITE"
"$CORE" -m venv "$VENV" || exit 10
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --only-binary :all: \
  cffi==2.1.1 cryptography==50.0.2 pycparser==3.11 || exit 11
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --no-deps "$WHEEL" || exit 12
export ENKSTEIN_POLICY_PACK=/nonexistent/macos-check PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH
status=0
cd "$ROOT/tests" && "$VENV/bin/python" ../tools/verify_scenarios.py --suite . --report macos-core-tests \
  --output "$EVIDENCE/macos-core-tests.json" > "$EVIDENCE/macos-core-tests.log" 2>&1 || status=1
cd "$ROOT" && "$VENV/bin/python" tools/verify_attack_scenarios.py --suite tests_adversarial \
  --output "$EVIDENCE/macos-attack-scenarios.json" > "$EVIDENCE/macos-attack-scenarios.log" 2>&1
[ $? -le 2 ] || status=1
if [ -n "$ENGINES" ]; then
  "$ENGINES" -m pip install --quiet --disable-pip-version-check --no-deps --target "$SITE" "$WHEEL" || exit 13
  cd "$ROOT/tests_optional" && PYTHONPATH="$SITE" "$ENGINES" ../tools/verify_scenarios.py --suite . \
    --report macos-optional-sdk-tests --output "$EVIDENCE/macos-optional-sdk-tests.json" \
    > "$EVIDENCE/macos-optional-sdk-tests.log" 2>&1 || status=1
fi
rm -rf "$SITE"
echo "macos_checks_status=$status"
