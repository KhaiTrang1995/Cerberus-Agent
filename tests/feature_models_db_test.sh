#!/usr/bin/env bash
# =============================================================================
# Models by feature: the featureModels merge, on real Postgres
# =============================================================================
# The settings PUT writes a user's per-feature models with ONE jsonb statement,
# `(feature_models || $set) - $removed`, so two tabs saving different features
# cannot drop each other's key (a Prisma read-modify-write would). The webapp's
# unit test can only see that the statement is a tagged template; this runs the
# statement itself.
#
# The SQL is read out of the route, not copied here, so an edit to it is what
# gets tested. It runs against a session-private TEMP copy of user_settings
# inside a transaction that is rolled back: no real row is read or written.
#
# Requires the stack's postgres container to be up:
#   docker compose up -d postgres
# Usage: tests/feature_models_db_test.sh
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."

ROUTE='webapp/src/app/api/users/[id]/settings/route.ts'
PSQL=(docker compose exec -T postgres psql -U redamon -d redamon -qtAX -v ON_ERROR_STOP=1)

pass=0
fail=0

ok()   { echo "  PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $1"; echo "        $2"; fail=$((fail + 1)); }

expect_eq() { # desc expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2' got '$3'"; fi
}

echo "== Models by feature: featureModels merge on Postgres =="

if ! "${PSQL[@]}" -c "select 1" >/dev/null 2>&1; then
  echo "  SKIP  postgres container not reachable (docker compose up -d postgres)"
  exit 0
fi

# The route's tagged template, with each ${...} turned into $1, $2, ... in order:
# ${JSON.stringify(patch.set)} -> $1, ${patch.removed} -> $2, ${userId} -> $3.
SQL=$(python3 - "$ROUTE" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"\$executeRaw`(.*?)`", src, re.S)
if not m:
    sys.exit("no $executeRaw tagged template in the route")
n = 0
def number(_):
    global n
    n += 1
    return f"${n}"
print(re.sub(r"\$\{[^}]*\}", number, m.group(1)).strip())
PY
)
if [ -z "$SQL" ]; then
  bad "the merge statement is found in the route" "no \$executeRaw template in $ROUTE"
  echo "== $pass passed, $fail failed =="
  exit 1
fi
ok "the merge statement is found in the route"

OUT=$("${PSQL[@]}" <<SQL 2>&1
BEGIN;
-- pg_temp is searched first, so the route's UPDATE lands on this copy.
CREATE TEMP TABLE user_settings (LIKE public.user_settings INCLUDING DEFAULTS) ON COMMIT DROP;
-- A HEAD-built webapp drops the column on restart until the schema is committed.
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS feature_models jsonb NOT NULL DEFAULT '{}'::jsonb;
INSERT INTO user_settings (id, user_id, updated_at) VALUES ('fm-row', 'fm-user', '2000-01-01');
PREPARE fm_merge(text, text[], text) AS $SQL;
EXECUTE fm_merge('{"triage":"gpt-5-mini"}', '{}', 'fm-user');
EXECUTE fm_merge('{"codefix":"claude-x"}', '{}', 'fm-user');
SELECT 'after_two:' || (SELECT feature_models::text FROM user_settings WHERE user_id = 'fm-user');
SELECT 'bumped:' || (SELECT (updated_at > '2000-01-02')::text FROM user_settings WHERE user_id = 'fm-user');
EXECUTE fm_merge('{}', '{triage}', 'fm-user');
SELECT 'after_remove:' || (SELECT feature_models::text FROM user_settings WHERE user_id = 'fm-user');
EXECUTE fm_merge('{"codefix":"claude-y"}', '{}', 'someone-else');
SELECT 'other_user:' || (SELECT feature_models::text FROM user_settings WHERE user_id = 'fm-user');
ROLLBACK;
SQL
)
rc=$?
if [ $rc -ne 0 ]; then
  bad "the merge statement runs on Postgres" "$OUT"
  echo "== $pass passed, $fail failed =="
  exit 1
fi
ok "the merge statement runs on Postgres"

field() { printf '%s\n' "$OUT" | sed -n "s/^$1://p" | head -1; }

expect_eq "a second feature's save keeps the first feature's model" \
  '{"triage": "gpt-5-mini", "codefix": "claude-x"}' "$(field after_two)"
expect_eq "the raw UPDATE bumps updated_at (it skips Prisma's @updatedAt)" "true" "$(field bumped)"
expect_eq "'' removes that feature's key and only that one" \
  '{"codefix": "claude-x"}' "$(field after_remove)"
expect_eq "a write for another user leaves this row alone" \
  '{"codefix": "claude-x"}' "$(field other_user)"

echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
