#!/usr/bin/env bash
# Exit criterion 1: the Proposer cannot read its own exam, and the refusal comes
# from BigQuery's authorization layer rather than from any code in this project.
#
# Three reads, every one as a real principal, straight against the BigQuery REST
# API so the refusal is the service's own words and not a wrapper's paraphrase:
#
#   proposer-sa on conduct_train   must succeed  (the identity itself works)
#   proposer-sa on holdout_sealed  must 403      (the seal)
#   examiner-sa on holdout_sealed  must succeed  (the exam has exactly one reader)
#
# The access token is held in a variable and never printed. The principal is
# proved from the token itself, not asserted by this script.
set -uo pipefail
source "$(dirname "$0")/env.sh"

API="https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries"

token_for() { gcloud auth print-access-token --impersonate-service-account="$1" 2>/dev/null; }

whoami_for() {
  curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("email","<unknown>"))'
}

query_as() {
  local tok="$1" sql="$2"
  curl -s -X POST "$API" -H "Authorization: Bearer ${tok}" -H "Content-Type: application/json" \
    -d "$(python3 -c 'import json,sys; print(json.dumps({"query": sys.argv[1], "useLegacySql": False}))' "$sql")"
}

render() { python3 "$(dirname "$0")/render_bq_result.py"; }

rule() { printf '%s\n' "==============================================================="; }

TOK_P="$(token_for "$SA_PROPOSER")"
TOK_E="$(token_for "$SA_EXAMINER")"
[ -n "$TOK_P" ] && [ -n "$TOK_E" ] || { echo "could not mint tokens"; exit 2; }

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
  echo "RESULT: *** SEAL FAILED - the Proposer read the holdout ***"; exit 1
fi
echo

rule; echo " 3. examiner-sa, the only principal granted the holdout"; rule
echo "principal on the wire: $(whoami_for "$TOK_E")"
echo "\$ SELECT COUNT(*) FROM ${PROJECT}.holdout_sealed.turns"
query_as "$TOK_E" "SELECT COUNT(*) AS events FROM \`${PROJECT}.holdout_sealed.turns\`" | render
echo

rule; echo " the holdout_sealed access list, as a reviewer reads it in the console"; rule
bq --project_id="$PROJECT" show --format=prettyjson "${PROJECT}:holdout_sealed" \
 | python3 -c "import json,sys; [print(f\"  {a.get('role'):<6} {a.get('userByEmail') or a.get('specialGroup') or a.get('groupByEmail')}\") for a in json.load(sys.stdin).get('access',[])]"

echo
rule; echo " 4. the same refusal in the Cloud Audit log, which names the permission"; rule
python3 "$(dirname "$0")/show_denial_audit.py" "$PROJECT" "$SA_PROPOSER"
