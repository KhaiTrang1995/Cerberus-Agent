#!/usr/bin/env bash
#
# Authenticated two-user BOLA E2E against the LIVE stack (enforcement ON).
#
# Proves per-user isolation end-to-end with real login sessions:
#   - a standard user cannot read another user's project / graph / export
#   - a standard user's project list is scoped to themselves
#   - an admin NOT simulating sees only their own data (no see-all)
#   - an admin simulating user A sees A's project, but pasting user B's project
#     URL while simulating A is BLOCKED (the operator-reported impersonation bug)
#   - a standard user cannot call the admin-only act-as endpoint
#
# Requires the stack up (webapp on :3000). Seeds + cleans up its own fixtures.
#
# Run: bash tests/test_e2e_bola_live.sh
set -uo pipefail

BASE="${BASE_URL:-http://localhost:3000}"
DC="docker compose"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; $DC exec -T webapp node scripts/e2e-bola-cleanup.mjs >/dev/null 2>&1 || true' EXIT

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ # desc expected actual
  if [ "$2" = "$3" ]; then ok "$1 -> $3"; else bad "$1 (expected $2, got $3)"; fi
}

login() { # email jarfile
  curl -s -o /dev/null -c "$2" -X POST "$BASE/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"e2epass123\"}"
}
code() { # jarfile method url [data]
  local jar="$1" method="$2" url="$3" data="${4:-}"
  if [ -n "$data" ]; then
    curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X "$method" \
      -H 'Content-Type: application/json' -d "$data" "$BASE$url"
  else
    curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" -X "$method" "$BASE$url"
  fi
}
body() { curl -s -b "$1" "$BASE$2"; }

echo "== Seeding fixtures =="
SEED="$($DC exec -T webapp node scripts/e2e-bola-seed.mjs)" || { echo "seed failed"; exit 1; }
echo "$SEED"
eval "$SEED"
[ -n "${PA_ID:-}" ] && [ -n "${PB_ID:-}" ] || { echo "seed did not yield project ids"; exit 1; }

echo "== Logging in =="
login bola-a@e2e.local     "$TMP/a.jar"
login bola-b@e2e.local     "$TMP/b.jar"
login bola-admin@e2e.local "$TMP/admin.jar"
# sanity: A is authenticated
check "user A session established" 200 "$(code "$TMP/a.jar" GET /api/auth/me)"

echo "== Standard-user isolation =="
check "A reads OWN project"                200 "$(code "$TMP/a.jar" GET "/api/projects/$PA_ID")"
check "A reads B's project -> blocked"     404 "$(code "$TMP/a.jar" GET "/api/projects/$PB_ID")"
check "A reads B's graph -> blocked"       404 "$(code "$TMP/a.jar" GET "/api/graph?projectId=$PB_ID")"
check "A exports B's project -> blocked"   404 "$(code "$TMP/a.jar" GET "/api/projects/$PB_ID/export")"
check "A deletes B's project -> blocked"   404 "$(code "$TMP/a.jar" DELETE "/api/projects/$PB_ID")"
check "A purges B's chains -> blocked"     404 "$(code "$TMP/a.jar" POST "/api/projects/$PB_ID/purge-orphan-chains")"

# A's project list must contain PA and NOT PB
LIST="$(body "$TMP/a.jar" /api/projects)"
if echo "$LIST" | grep -q "$PA_ID"; then ok "A's project list includes own PA"; else bad "A's list missing PA"; fi
if echo "$LIST" | grep -q "$PB_ID"; then bad "A's project list LEAKS B's PB"; else ok "A's project list excludes B's PB"; fi

echo "== A3-cont resources (conversations / remediations / presets) =="
check "A lists B's conversations -> blocked"        404 "$(code "$TMP/a.jar" GET "/api/conversations?projectId=$PB_ID")"
check "A reads B's conversation by-session -> blocked" 404 "$(code "$TMP/a.jar" GET "/api/conversations/by-session/$CONV_B_SESSION")"
check "A lists B's remediations -> blocked"          404 "$(code "$TMP/a.jar" GET "/api/remediations?projectId=$PB_ID")"
check "A reads B's remediation by id -> blocked"     404 "$(code "$TMP/a.jar" GET "/api/remediations/$REM_B_ID")"
check "A reads B's report list -> blocked"           404 "$(code "$TMP/a.jar" GET "/api/projects/$PB_ID/reports")"
check "A reads B's graph-views -> blocked"           404 "$(code "$TMP/a.jar" GET "/api/graph-views?projectId=$PB_ID")"
check "A deletes B's preset by id -> blocked"        404 "$(code "$TMP/a.jar" DELETE "/api/presets/$PRESET_B_ID")"
# A's preset list must exclude B's preset
PLIST="$(body "$TMP/a.jar" /api/presets)"
if echo "$PLIST" | grep -q "$PRESET_B_ID"; then bad "A's preset list LEAKS B's preset"; else ok "A's preset list excludes B's preset"; fi
# Mute Rules presets: a user's own, 404 to anyone else exactly like a missing id
check "A reads B's mute-rules preset -> blocked"     404 "$(code "$TMP/a.jar" GET "/api/mute-rule-presets/$MUTE_PRESET_B_ID")"
check "A renames B's mute-rules preset -> blocked"   404 "$(code "$TMP/a.jar" PATCH "/api/mute-rule-presets/$MUTE_PRESET_B_ID" '{"name":"taken"}')"
check "A deletes B's mute-rules preset -> blocked"   404 "$(code "$TMP/a.jar" DELETE "/api/mute-rule-presets/$MUTE_PRESET_B_ID")"
MPLIST="$(body "$TMP/a.jar" /api/mute-rule-presets)"
if echo "$MPLIST" | grep -q "$MUTE_PRESET_B_ID"; then bad "A's mute-rules preset list LEAKS B's preset"; else ok "A's mute-rules preset list excludes B's preset"; fi
check "B reads OWN mute-rules preset (the 404s are real)" 200 "$(code "$TMP/b.jar" GET "/api/mute-rule-presets/$MUTE_PRESET_B_ID")"

echo "== A5 resources (scan / analytics / workspace / user-scoped) =="
check "A starts a scan on B's project -> blocked"   404 "$(code "$TMP/a.jar" POST "/api/recon/$PB_ID/start")"
check "A reads B's scan status -> blocked"          404 "$(code "$TMP/a.jar" GET "/api/recon/$PB_ID/status")"
check "A reads B's analytics vulns -> blocked"      404 "$(code "$TMP/a.jar" GET "/api/analytics/vulnerabilities?projectId=$PB_ID")"
check "A reads B's redzone secrets -> blocked"      404 "$(code "$TMP/a.jar" GET "/api/analytics/redzone/secrets?projectId=$PB_ID")"
check "A lists B's workspace files -> blocked"      404 "$(code "$TMP/a.jar" GET "/api/agent/workspace/list?projectId=$PB_ID&path=/")"
check "A reads B's MCP servers -> blocked"          403 "$(code "$TMP/a.jar" GET "/api/users/$B_ID/mcp")"
check "A reads B's attack-skills -> blocked"        403 "$(code "$TMP/a.jar" GET "/api/users/$B_ID/attack-skills")"

echo "== API usage report (sends a user's plaintext keys to providers) =="
# The seeded users have no keys, so no provider is ever called: an owner POST
# answers 400 no_keys, and a refused cross-user POST never reaches the keys.
B_USAGE_BEFORE="$(body "$TMP/b.jar" "/api/users/$B_ID/settings/api-usage")"
check "A reads B's api-usage report -> blocked"     403 "$(code "$TMP/a.jar" GET "/api/users/$B_ID/settings/api-usage")"
check "A runs B's api-usage check -> blocked"       403 "$(code "$TMP/a.jar" POST "/api/users/$B_ID/settings/api-usage" '{"overwrite":true,"ignoreRunningScans":true}')"
B_USAGE_AFTER="$(body "$TMP/b.jar" "/api/users/$B_ID/settings/api-usage")"
if [ -n "$B_USAGE_BEFORE" ] && [ "$B_USAGE_BEFORE" = "$B_USAGE_AFTER" ]; then ok "B's api-usage state unchanged by A's POST"; else bad "B's api-usage state changed (or unreadable) after A's POST"; fi
check "B reads OWN api-usage (the 403s are real)"   200 "$(code "$TMP/b.jar" GET "/api/users/$B_ID/settings/api-usage")"

echo "== Admin scoping + impersonation =="
check "admin (not simulating) reads A's project -> blocked (no see-all)" 404 "$(code "$TMP/admin.jar" GET "/api/projects/$PA_ID")"
check "admin (not simulating) reads A's api-usage -> blocked" 403 "$(code "$TMP/admin.jar" GET "/api/users/$A_ID/settings/api-usage")"
check "admin (not simulating) runs A's api-usage -> blocked"  403 "$(code "$TMP/admin.jar" POST "/api/users/$A_ID/settings/api-usage" '{"overwrite":true}')"
check "admin acts-as A"                                    200 "$(code "$TMP/admin.jar" POST /api/auth/act-as "{\"targetUserId\":\"$A_ID\"}")"
check "admin simulating A reads A's project"              200 "$(code "$TMP/admin.jar" GET "/api/projects/$PA_ID")"
check "admin simulating A pastes B's project -> BLOCKED"  404 "$(code "$TMP/admin.jar" GET "/api/projects/$PB_ID")"
check "admin simulating A reads A's api-usage"            200 "$(code "$TMP/admin.jar" GET "/api/users/$A_ID/settings/api-usage")"
check "admin simulating A reads B's api-usage -> BLOCKED" 403 "$(code "$TMP/admin.jar" GET "/api/users/$B_ID/settings/api-usage")"
check "admin stops simulating"                            200 "$(code "$TMP/admin.jar" DELETE /api/auth/act-as)"
check "admin (stopped) reads A's project -> blocked again" 404 "$(code "$TMP/admin.jar" GET "/api/projects/$PA_ID")"

echo "== Owner path still works (non-breaking) =="
check "A reads OWN analytics vulns"                 200 "$(code "$TMP/a.jar" GET "/api/analytics/vulnerabilities?projectId=$PA_ID")"
check "A reads OWN redzone secrets"                 200 "$(code "$TMP/a.jar" GET "/api/analytics/redzone/secrets?projectId=$PA_ID")"
check "A reads OWN scan status"                     200 "$(code "$TMP/a.jar" GET "/api/recon/$PA_ID/status")"
check "A lists OWN remediations"                    200 "$(code "$TMP/a.jar" GET "/api/remediations?projectId=$PA_ID")"
check "A lists OWN conversations"                   200 "$(code "$TMP/a.jar" GET "/api/conversations?projectId=$PA_ID")"
check "A lists OWN graph-views"                     200 "$(code "$TMP/a.jar" GET "/api/graph-views?projectId=$PA_ID")"
check "A reads OWN api-usage report"                200 "$(code "$TMP/a.jar" GET "/api/users/$A_ID/settings/api-usage")"
check "A runs OWN api-usage check (no keys saved)"  400 "$(code "$TMP/a.jar" POST "/api/users/$A_ID/settings/api-usage" '{}')"
# legacy agent/files download (no projectId) must NOT be blocked by the project guard
FILES_CODE="$(code "$TMP/a.jar" GET "/api/agent/files?path=/tmp/nonexistent")"
if [ "$FILES_CODE" = "400" ]; then bad "legacy agent/files (no projectId) wrongly 400-blocked"; else ok "legacy agent/files (no projectId) not project-guard-blocked -> $FILES_CODE"; fi

echo "== ws-ticket is scoped to the effective user's project =="
check "A mints a ws-ticket for OWN project"        200 "$(code "$TMP/a.jar" POST /api/agent/ws-ticket "{\"projectId\":\"$PA_ID\",\"sessionId\":\"s1\"}")"
check "A mints a ws-ticket for B's project -> blocked" 404 "$(code "$TMP/a.jar" POST /api/agent/ws-ticket "{\"projectId\":\"$PB_ID\",\"sessionId\":\"s1\"}")"

echo "== Privilege: standard user cannot impersonate =="
check "A calls admin-only act-as -> 403" 403 "$(code "$TMP/a.jar" POST /api/auth/act-as "{\"targetUserId\":\"$B_ID\"}")"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
