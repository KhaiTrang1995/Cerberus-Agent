#!/usr/bin/env bash
# =============================================================================
# LIVE check: every image that bakes graph_db ships the lock-first prune.
#
# The prune and the GVM / GitHub-hunt / TruffleHog clears take a write lock on a
# finding (`SET n._prune_lock = true REMOVE n._prune_lock`) before they read
# n:Muted. Without it, a mute committing between the read and the DETACH DELETE
# is lost: MCP mute_findings reports the finding muted and the prune deletes it.
#
# The fix lives in graph_db, and graph_db reaches a scan three ways:
#   - recon, gvm and github-hunt COPY it into the image. The orchestrator binds
#     the host's graph_db over that copy only when it can detect the host path
#     (container_manager._graph_db_mount); on Docker Desktop / WSL2 it cannot,
#     and the BAKED copy runs. A stale image there silently keeps the race.
#   - the agent COPYs it (its triage ops run the same mixins).
#   - trufflehog bakes none: its container holds no Neo4j credentials, and the
#     graph write runs in the recon-orchestrator, which mounts ./graph_db live.
#
# So this asserts the lock in the baked copy of each baking image, and that the
# trufflehog image still bakes no graph_db (a copy added later would need this
# check too).
#
# Not part of `./redamon.sh test` (the gate matches tests/*_test.sh only). Run
# after rebuilding the scan images:
#     bash tests/graph_db_baked_copy_live.sh
# =============================================================================
set -uo pipefail

PASS=0; FAIL=0; CHECKED=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
skip() { echo "  SKIP  $1"; exit 0; }

command -v docker >/dev/null 2>&1 || skip "docker unavailable (graph_db baked copy)"
docker info >/dev/null 2>&1        || skip "docker daemon unreachable (graph_db baked copy)"

BAKING_IMAGES=(
    redamon-recon:latest
    redamon-vuln-scanner:latest
    redamon-github-hunter:latest
    redamon-agent:latest
)
LOCKED_FILES=(mixins/base_mixin.py mixins/secret_mixin.py)

# Resolves graph_db the way the scan's own `import graph_db` does, so a copy at
# an unexpected path is still the one checked. --network none: nothing here
# needs the network, and the image's entrypoint (a scan) is bypassed.
graph_db_dir() {
    docker run --rm --network none --entrypoint python3 "$1" -c '
import importlib.util as u
s = u.find_spec("graph_db")
print(s.submodule_search_locations[0] if s else "")' 2>/dev/null | tail -1
}

echo "graph_db baked copies ship the lock-first prune"
for image in "${BAKING_IMAGES[@]}"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "  SKIP  $image not built locally"
        continue
    fi
    CHECKED=$((CHECKED+1))
    dir="$(graph_db_dir "$image")"
    if [[ -z "$dir" ]]; then
        bad "$image bakes graph_db" "no graph_db package" "an importable graph_db"
        continue
    fi
    for rel in "${LOCKED_FILES[@]}"; do
        count="$(docker run --rm --network none --entrypoint sh "$image" \
            -c "grep -c '_prune_lock' '$dir/$rel' 2>/dev/null || true")"
        count="${count:-0}"
        if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
            ok "$image $rel takes _prune_lock ($count)"
        else
            bad "$image $rel takes _prune_lock" "$count" ">0 (rebuild the image from the current tree)"
        fi
    done
done

if docker image inspect redamon-trufflehog:latest >/dev/null 2>&1; then
    CHECKED=$((CHECKED+1))
    dir="$(graph_db_dir redamon-trufflehog:latest)"
    if [[ -z "$dir" ]]; then
        ok "redamon-trufflehog bakes no graph_db (its graph write runs in the orchestrator)"
    else
        bad "redamon-trufflehog bakes no graph_db" "$dir" "none: add it to BAKING_IMAGES"
    fi
else
    echo "  SKIP  redamon-trufflehog:latest not built locally"
fi

(( CHECKED > 0 )) || skip "none of the graph_db images is built locally"

echo
echo "graph_db baked copy: $PASS passed, $FAIL failed"
(( FAIL == 0 ))
