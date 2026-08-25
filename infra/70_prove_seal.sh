#!/usr/bin/env bash
# Exit criterion 1: the Proposer cannot read its own exam, and the refusal comes
# from BigQuery's authorization layer rather than from any code in this project.
#
# Reads made as real principals, straight against the BigQuery REST API so the
# refusal is the service's own words and not a wrapper's paraphrase:
#
#   proposer-sa  on conduct_train   must succeed  (the identity itself works)
#   proposer-sa  on holdout_sealed  must 403      (the seal)
#   examiner-sa  on holdout_sealed  must succeed  (the exam has exactly one reader)
#   the operator on holdout_sealed  must 403      (the seal is not just for robots)
#
# The access token is never printed and never placed in a command argument or a
# URL, both of which are visible in the local process table. The principal is
# proved from the token itself, not asserted by this script.
set -uo pipefail
source "$(dirname "$0")/env.sh"
HERE="$(dirname "$0")"

API="https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries"

token_for() { gcloud auth print-access-token --impersonate-service-account="$1" 2>/dev/null; }

whoami_for() {
  # POST body read from stdin: the token never appears in argv.
  printf 'access_token=%s' "$1" \
    | curl -s -X POST --data @- "https://oauth2.googleapis.com/tokeninfo" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("email","<unknown>"))'
}

query_as() {
  local tok="$1" sql="$2"
  python3 -c 'import json,sys; print(json.dumps({"query": sys.argv[1], "useLegacySql": False}))' "$sql" \
    | curl -s -X POST "$API" -H "Authorization: Bearer ${tok}" \
           -H "Content-Type: application/json" --data @-
}

render() { python3 "$HERE/render_bq_result.py"; }
rule() { printf '%s\n' "==============================================================="; }

TOK_P="$(token_for "$SA_PROPOSER")"
TOK_E="$(token_for "$SA_EXAMINER")"
TOK_ME="$(gcloud auth print-access-token 2>/dev/null)"

# BigQuery caches dataset access lists for a few minutes. Immediately after
# 40_seal_holdout.sh the old list is still being served, so a read this script
# expects to fail still succeeds. Wait for the seal to be the one in force
# rather than capturing a stale answer as a result.
settled() {
  python3 -c 'import json,sys; sys.exit(0 if "error" in json.load(sys.stdin) else 1)' \
    < <(query_as "$TOK_ME" "SELECT COUNT(*) AS n FROM \`${PROJECT}.holdout_sealed.turns\`")
}
for _ in $(seq 1 40); do settled && break; sleep 15; done
[ -n "$TOK_P" ] && [ -n "$TOK_E" ] || {
  echo "could not mint tokens. 10_service_accounts.sh grants the token-creator role."
  exit 2
}

FAILED=0

rule; echo " 1. proposer-sa reads the training window it is entitled to"; rule
echo "principal on the wire: $(whoami_for "$TOK_P")"
echo "\$ SELECT COUNT(*) FROM ${PROJECT}.conduct_train.turns"
query_as "$TOK_P" "SELECT COUNT(*) AS events FROM \`${PROJECT}.conduct_train.turns\`" | render
echo

rule; echo " 2. the same principal reads the sealed holdout"; rule
echo "principal on the wire: $(whoami_for "$TOK_P")"
echo "\$ SELECT COUNT(*) FROM ${PROJECT}.holdout_sealed.turns"
OUT="$(query_as "$TOK_P" "SELECT COUNT(*) AS events FROM \`${PROJECT}.holdout_sealed.turns\`")"
echo "$OUT" | render
echo
if echo "$OUT" | grep -q "PERMISSION_DENIED\|accessDenied"; then
  echo "RESULT: DENIED by BigQuery. No code in this project ran."
else
  echo "RESULT: *** SEAL FAILED - the Proposer read the holdout ***"; FAILED=1
fi
echo

rule; echo " 3. examiner-sa, the only principal on the holdout's access list"; rule
echo "principal on the wire: $(whoami_for "$TOK_E")"
echo "\$ SELECT COUNT(*) FROM ${PROJECT}.holdout_sealed.turns"
query_as "$TOK_E" "SELECT COUNT(*) AS events FROM \`${PROJECT}.holdout_sealed.turns\`" | render
echo

rule; echo " 4. the human project owner attempts the same read"; rule
echo "  The seal is not only aimed at the fleet. bigquery.tables.getData is not"
echo "  part of roles/owner, so once the inherited entries are off the dataset the"
echo "  owner of the project is refused it as well."
echo
echo "principal on the wire: $(whoami_for "$TOK_ME")"
echo "\$ SELECT COUNT(*) FROM ${PROJECT}.holdout_sealed.turns"
MINE="$(query_as "$TOK_ME" "SELECT COUNT(*) AS events FROM \`${PROJECT}.holdout_sealed.turns\`")"
echo "$MINE" | render
echo
if echo "$MINE" | grep -q "PERMISSION_DENIED\|accessDenied"; then
  echo "RESULT: the project owner is DENIED the exam."
else
  echo "RESULT: *** the project owner can read the exam ***"; FAILED=1
fi
echo

rule; echo " the holdout_sealed access list, as a reviewer reads it in the console"; rule
ACL="$(bq --project_id="$PROJECT" show --format=prettyjson "${PROJECT}:holdout_sealed")"
echo "$ACL" | python3 -c "import json,sys; [print(f\"  {a.get('role'):<6} {a.get('userByEmail') or a.get('specialGroup') or a.get('groupByEmail')}\") for a in json.load(sys.stdin).get('access',[])]"
echo
# The list is the artifact the demo puts on screen, so its shape is asserted
# rather than displayed and trusted. An extra entry appearing here used to go
# unremarked in a committed capture.
if ! echo "$ACL" | python3 -c "
import json, sys
access = json.load(sys.stdin).get('access', [])
expected = [{'role': 'OWNER', 'userByEmail': '${SA_EXAMINER}'}]
sys.exit(0 if access == expected else 1)
"; then
  echo "RESULT: *** the holdout access list is not exactly one entry for examiner-sa ***"
  FAILED=1
else
  echo "RESULT: exactly one entry, and it is the Examiner."
fi

echo
rule; echo " 5. the same refusal in the Cloud Audit log, which names the permission"; rule
python3 "$HERE/show_denial_audit.py" "$PROJECT" "$SA_PROPOSER" || FAILED=1

exit "$FAILED"
