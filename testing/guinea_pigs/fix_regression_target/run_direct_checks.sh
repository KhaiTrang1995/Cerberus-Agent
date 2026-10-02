#!/usr/bin/env bash
# The pre-fix and the fixed security checks against the live lab, side by side.
#   ./run_direct_checks.sh [old-git-ref]     (default c2794cb6, the last commit before the fixes)
set -euo pipefail
REF="${1:-c2794cb6}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# Snap Docker cannot bind-mount /tmp or a hidden folder, so the old module goes
# in a plain folder under $HOME.
OLD="$HOME/fixreg-old-$$"
mkdir -p "$OLD"
trap 'rm -rf "$OLD"' EXIT
git -C "$REPO" show "$REF:recon/helpers/security_checks.py" > "$OLD/security_checks.py"
docker run --rm --network host -v "$REPO:/repo" -v "$OLD:/old:ro" -v "$HERE:/lab:ro" \
    -w /repo -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon /lab/direct_checks.py \
    2>&1 | grep -E "^ (OLD|NEW)|^=="
