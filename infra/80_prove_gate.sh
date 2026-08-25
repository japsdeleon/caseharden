#!/usr/bin/env bash
# Day 2 exit criterion: the promotion gate is a property of the code, not of the
# demo. Every case below runs the real Examiner against the real BigQuery
# corpora as examiner-sa, and this script asserts the outcome rather than
# printing it for a reader to judge.
#
#   1. the Proposer asks to score its own draft            must be REFUSED
#   2. a candidate with a better catch rate on every family must be DENIED,
#      because it denies a third of legitimate traffic
#   3. a candidate that drops a rule the active version carries must be DENIED
#      for widening authority, even though it catches more and blocks nothing
#      legitimate
#   4. the candidate that improves both sides must PASS
#   5. the scoring jobs must appear in BigQuery job history under examiner-sa
set -uo pipefail
source "$(dirname "$0")/env.sh"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

FAILED=0
rule() { printf '%s\n' "==============================================================="; }

# Runs the Examiner and checks both the exit code and the banner. The exit code
# alone is not enough: a denial for the wrong reason is a different bug.
expect() {
  local label="$1" want_code="$2" want_text="$3"; shift 3
  local out code
  out="$("$@" 2>&1)"; code=$?
  echo "$out"
  echo
  if [ "$code" = "$want_code" ] && printf '%s' "$out" | grep -q "$want_text"; then
    echo "RESULT: $label"
  else
    echo "RESULT: *** $label FAILED - exit $code (wanted $want_code), expected text: $want_text ***"
    FAILED=1
  fi
  echo
}

EXAMINER=(python3 -m caseharden.examiner --backend bq)

rule; echo " 1. the Proposer asks the Examiner to score its own draft"; rule
echo "\$ python3 -m caseharden.examiner --candidate v4 --backend bq --impersonate proposer-sa"
expect "the Proposer cannot score itself against the sealed holdout" 3 "PERMISSION_DENIED" \
  "${EXAMINER[@]}" --candidate policies/v4-candidate-b.json --impersonate "$SA_PROPOSER"

rule; echo " 2. candidate A. Catches more on every family. Over-blocks."; rule
expect "the over-blocking candidate is denied on the benign side" 1 "REASON: BENIGN REGRESSION" \
  "${EXAMINER[@]}" --candidate policies/v4-candidate-a.json

rule; echo " 3. candidate W. Catches more, blocks nothing legitimate, widens."; rule
expect "the widening candidate is denied on monotonicity" 1 "REASON: AUTHORITY WIDENED" \
  "${EXAMINER[@]}" --candidate policies/v4-candidate-widening.json

rule; echo " 4. candidate B, and the two engines checked against each other"; rule
echo "  --check-equivalence runs the compiled BigQuery predicate and the Python"
echo "  evaluator over the same corpora and compares the set of turns each denied."
echo "  Two implementations of one grammar are only worth having if they agree."
echo
expect "the improving candidate passes all three legs" 0 "GATE PASS" \
  "${EXAMINER[@]}" --candidate policies/v4-candidate-b.json --check-equivalence

rule; echo " 5. who BigQuery says ran the scoring jobs"; rule
JOBS="$(bq --project_id="$PROJECT" query --nouse_legacy_sql --format=csv --location="$BQ_LOCATION" \
  'SELECT user_email, COUNT(*) AS jobs FROM `region-europe-west3`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
   WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 20 MINUTE)
     AND statement_type = "SELECT" GROUP BY user_email ORDER BY jobs DESC' 2>/dev/null)"
echo "$JOBS"
echo
if printf '%s' "$JOBS" | grep -q "^${SA_EXAMINER},"; then
  echo "RESULT: the scoring ran as examiner-sa."
else
  echo "RESULT: *** no scoring jobs attributed to examiner-sa ***"
  FAILED=1
fi

echo
rule
[ "$FAILED" = 0 ] && echo " DAY 2 EXIT CRITERION MET. The gate refuses three ways and passes one." \
                  || echo " *** DAY 2 EXIT CRITERION NOT MET ***"
rule
exit "$FAILED"
