#!/usr/bin/env bash
# =============================================================================
# Regression: recon/entrypoint.sh refreshed resolvers.txt IN PLACE with
# `curl -sL -o`. Without -f an HTTP error page was written over the list and
# reported as a success, and a cut transfer left half a list behind; scans then
# copied it into the shared /tmp/redamon list puredns reads.
#
# The resolver block is cut out of the entrypoint (banner to banner) and run
# against a sandbox file with `curl` stubbed, so no network and no container.
#   bash tests/recon_resolvers_refresh_test.sh
# RESOLVERS_ENTRYPOINT=<path> runs the same checks against another copy.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENTRYPOINT="${RESOLVERS_ENTRYPOINT:-$REPO_ROOT/recon/entrypoint.sh}"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
LIST="$SANDBOX/resolvers.txt"
GOOD_OLD=$'9.9.9.9\n1.1.1.1'
GOOD_NEW=$'8.8.8.8\n8.8.4.4\n1.0.0.1'

BLOCK="$(awk '/^# Download DNS resolvers/{on=1} /^# Pull required Docker images/{on=0} on' "$ENTRYPOINT")"
if [[ "$BLOCK" != *'RESOLVER_FILE="/app/recon/data/resolvers.txt"'* ]]; then
    echo "resolver block not found in $ENTRYPOINT"
    exit 1
fi
BLOCK="${BLOCK//\/app\/recon\/data\/resolvers.txt/$LIST}"

# Runs the block the way the entrypoint does (set -e), with curl answering as
# CURL_MODE says: ok | error_page (404) | partial (cut transfer) | captive (200
# HTML). Like the real curl, -f turns an HTTP error into exit 22, no output.
run_block() {
    CURL_MODE="$1" CURL_CALLS="$SANDBOX/curl_calls" bash -c '
        set -e
        RED=""; GREEN=""; YELLOW=""; NC=""
        curl() {
            local out="" fail_flag=0 prev=""
            for arg in "$@"; do
                [[ "$prev" == "-o" ]] && out="$arg"
                [[ "$arg" == "--fail" || "$arg" =~ ^-[a-zA-Z]*f[a-zA-Z]*$ ]] && fail_flag=1
                prev="$arg"
            done
            echo call >> "$CURL_CALLS"
            case "$CURL_MODE" in
                ok)         printf "8.8.8.8\n8.8.4.4\n1.0.0.1\n" > "$out"; return 0 ;;
                error_page) [[ $fail_flag == 1 ]] && return 22
                            printf "<html><body>404: Not Found</body></html>\n" > "$out"; return 0 ;;
                partial)    printf "8.8.8.8\n8.8" > "$out"; return 18 ;;
                captive)    printf "<html><body>Sign in to the network</body></html>\n" > "$out"; return 0 ;;
            esac
        }
        eval "$1"
    ' _ "$BLOCK" >/dev/null 2>&1
}

stale_list() {
    rm -f "$SANDBOX"/curl_calls "$SANDBOX"/.resolvers.txt.*
    printf '%s\n' "$GOOD_OLD" > "$LIST"
    touch -t 200001010000 "$LIST"   # POSIX -t: older than the 7-day refresh
}

leftovers() { find "$SANDBOX" -maxdepth 1 -name '.resolvers.txt.*' | wc -l | tr -d ' '; }

echo "== recon entrypoint: resolver refresh =="

stale_list; run_block error_page; rc=$?
assert_eq "test_regression_resolvers_error_page_replaced_list" "$(cat "$LIST")" "$GOOD_OLD"
assert_eq "an error page does not abort the entrypoint" "$rc" "0"

stale_list; run_block partial
assert_eq "test_regression_resolvers_partial_download_replaced_list" "$(cat "$LIST")" "$GOOD_OLD"

stale_list; run_block captive
assert_eq "a 200 page that is not a resolver list is refused" "$(cat "$LIST")" "$GOOD_OLD"
assert_eq "a refused download leaves no temp file" "$(leftovers)" "0"

stale_list; run_block ok
assert_eq "a good download replaces a week-old list" "$(cat "$LIST")" "$GOOD_NEW"
assert_eq "a good download leaves no temp file" "$(leftovers)" "0"

rm -f "$LIST" "$SANDBOX/curl_calls"; run_block ok
assert_eq "a missing list is downloaded" "$(cat "$LIST")" "$GOOD_NEW"

stale_list; touch "$LIST"; run_block ok
assert_eq "a list under a week old is not re-downloaded" "$(cat "$LIST")" "$GOOD_OLD"
assert_eq "no curl call for a fresh list" "$([[ -f "$SANDBOX/curl_calls" ]] && echo called || echo none)" "none"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
