#!/usr/bin/env bash
# The analyst surface: one identity, one table, and nothing else it can touch.
#
# The Analyst Copilot is a human's chat window, so it is the least trusted
# component in the fleet: whatever it can reach, a person typing into a text box
# can reach. It gets its own service account and its own dataset.
#
# `review.decisions` is separate from `policy` on purpose. WRITER on a dataset
# carries DML delete, so putting the analyst's writes in `policy` would let the
# chat window delete rows from the version registry. The Notary reads
# `review.decisions` to build the VERDICT and APPROVAL links; the Copilot cannot
# read the chain, cannot read the policy registry, and cannot read any conduct.
set -euo pipefail
source "$(dirname "$0")/env.sh"
HERE="$(cd "$(dirname "$0")" && pwd)"

SA_ANALYST="analyst-sa@${PROJECT}.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe "$SA_ANALYST" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud iam service-accounts create analyst-sa \
    --display-name="Caseharden Analyst Copilot" \
    --description="The human review surface. Writes verdicts and approvals, reads nothing else." \
    --project="$PROJECT" --quiet >/dev/null
  echo "created analyst-sa"
else
  echo "exists  analyst-sa"
fi

OPERATOR="${CASEHARDEN_OPERATOR:-$(gcloud config get-value account 2>/dev/null)}"
gcloud iam service-accounts add-iam-policy-binding "$SA_ANALYST" \
  --member="user:${OPERATOR}" --role=roles/iam.serviceAccountTokenCreator \
  --project="$PROJECT" --quiet >/dev/null

if ! bq --project_id="$PROJECT" show "${PROJECT}:review" >/dev/null 2>&1; then
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" mk --dataset \
    --description="What a human decided: verdicts on findings, approvals of candidates." \
    "${PROJECT}:review" >/dev/null
  echo "created dataset review"
else
  echo "exists  dataset review"
fi

# One row per human decision. `kind` is VERDICT or APPROVAL; the Model Armor
# columns carry the screening of the analyst's own free text, because an
# analyst's keyboard is an untrusted input like any other.
if ! bq --project_id="$PROJECT" show "${PROJECT}:review.decisions" >/dev/null 2>&1; then
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" mk --table \
    "${PROJECT}:review.decisions" \
    "decision_id:STRING,ts:TIMESTAMP,kind:STRING,analyst:STRING,subject:STRING,\
disposition:STRING,rationale:STRING,ma_verdict:STRING,ma_band:STRING,\
ma_prompt_injection_score:FLOAT,ma_jailbreak_score:FLOAT,approved:BOOLEAN" >/dev/null
  echo "created review.decisions"
else
  echo "exists  review.decisions"
fi

# The columns added after the table already existed, and the reason the branch
# above cannot carry them. `mk --table` runs only when the table is absent, so
# on any project that has run this script once, a column named in that schema
# string is a column the table never gains. The else branch printed a line and
# did nothing. Everything below runs on both paths.
#
# What they hold. `cited_policy_id` and `cited_version` are the policy the
# analyst was applying: without them a verdict cannot be explained a month
# later, because nothing on the row says which policy line, or which version of
# it, the person had in mind. `citation_source` separates a citation the analyst
# chose ('ANALYST') from a row that carries none ('NONE'); a component able to
# compute the window default would write 'DEFAULTED', and none exists, so the
# two cases that do occur can never be read as each other. The three `advisory_`
# columns are the machine's recommendation, rule and confidence AS DISPLAYED to
# the analyst beside the verdict box. Nothing in this repository produces that
# triple yet, so they are NULL on every row the fleet writes today; they are
# shaped for the recommender that will, because a recommendation recomputed at
# read time proves nothing about what the human was looking at.
#
# `advisory_source` says who asserted the advisory, and it exists for the same
# reason `citation_source` does. The three columns above are taken from whatever
# called the tool, and nothing in the fleet emits that triple, so a stored
# advisory is a claim by the recording surface and not a recommendation anyone
# can attribute to a recommender. Without this column the console said "the
# machine advised X, as it was displayed beside this verdict", which is a
# sentence the record cannot support: an analyst could attribute their own call
# to a recommendation that never existed and no auditor could contradict it.
# 'SURFACE' is what a row written today carries, 'NONE' is no advisory at all,
# and 'RECOMMENDER' is reserved for a component that produces one and can be
# named as its author.
#
# They are safe to add. THREATS.md entry 10 is about `conduct_live.turns`, whose
# rows the chain digests as `SHA256(TO_JSON_STRING(t))`, where one new column
# changes every cited digest and quarantines every chain in the project.
# `review.decisions` is read by explicit column list everywhere it is read —
# caseharden/notary.py's corroboration, infra/110_run_loop.py's poll,
# caseharden/workbench.py's DECISION_COLUMNS — and no digest is taken over it,
# so nothing here moves an attestation.
#
# Order against the Copilot. agents/copilot/agent.py names all six keys on every
# verdict it writes, and tabledata.insertAll rejects a row naming a column the
# table does not have. Run this script before deploying the Copilot. A missed
# migration then fails loudly on the first verdict rather than quietly dropping
# the citation, which is the right way round. Google documents a lag between a
# schema change and the streaming path seeing it; that lag is not measured here.
DECISION_COLUMNS_ADDED="cited_policy_id cited_version citation_source \
advisory_recommendation advisory_rule advisory_confidence advisory_source"

# Read the schema before the change, so the script can say what it did rather
# than only what it ran. The ALTER itself is unconditional and idempotent, so a
# wrong answer here costs a misleading line of output and never a skipped
# migration.
#
# The report is a read before a write with no transaction between them, so two
# operators running this at once can both read the columns as absent and both
# claim to have added them. An adversarial pass named the race. It is not closed:
# BigQuery gives no way to learn which ADD COLUMN clauses in a statement did
# anything, and a second read afterwards is the same race one step later. What is
# guaranteed is the migration, not the sentence about it, and the sentence is a
# line of operator output rather than anything the chain reads.
BEFORE="$(bq --project_id="$PROJECT" show --schema --format=prettyjson \
  "${PROJECT}:review.decisions" \
  | python3 -c 'import json,sys; print(" ".join(f["name"] for f in json.load(sys.stdin)))')"
ADDING=""
for column in $DECISION_COLUMNS_ADDED; do
  case " $BEFORE " in
    *" $column "*) ;;
    *) ADDING="$ADDING $column" ;;
  esac
done

bq --project_id="$PROJECT" --location="$BQ_LOCATION" query --use_legacy_sql=false --quiet \
  "ALTER TABLE \`${PROJECT}.review.decisions\`
     ADD COLUMN IF NOT EXISTS cited_policy_id STRING,
     ADD COLUMN IF NOT EXISTS cited_version STRING,
     ADD COLUMN IF NOT EXISTS citation_source STRING,
     ADD COLUMN IF NOT EXISTS advisory_recommendation STRING,
     ADD COLUMN IF NOT EXISTS advisory_rule STRING,
     ADD COLUMN IF NOT EXISTS advisory_confidence FLOAT64,
     ADD COLUMN IF NOT EXISTS advisory_source STRING" >/dev/null

if [ -n "$ADDING" ]; then
  echo "altered review.decisions, added:$ADDING"
  echo "        rows written before this carry NULL in all six. A NULL"
  echo "        citation_source is a row that predates the column, not a verdict"
  echo "        that cited nothing; 'NONE' is that one."
else
  echo "exists  review.decisions citation and advisory columns"
fi

python3 "${HERE}/bq_grant.py" "$PROJECT" review WRITER "$SA_ANALYST"
python3 "${HERE}/bq_grant.py" "$PROJECT" review READER "$SA_NOTARY"

# The model and the screener. Nothing that reads conduct, the chain, or the exam.
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA_ANALYST}" \
  --role=roles/aiplatform.user --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA_ANALYST}" \
  --role=roles/modelarmor.user --condition=None --quiet >/dev/null
# A BigQuery job runs in a project; the WRITER above is on the dataset only.
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA_ANALYST}" \
  --role=roles/bigquery.jobUser --condition=None --quiet >/dev/null
echo "granted the model, the screener and job-user to analyst-sa"

# Assert the boundary rather than trusting the grants above. The analyst surface
# reading the sealed exam would make every measurement in the chain worthless.
# The tokenCreator binding above needs up to a minute to propagate, and a fresh
# service account is refused until it does. Retry rather than concluding the
# grant failed.
TOKEN=""
for attempt in 1 2 3 4 5 6; do
  TOKEN="$(gcloud auth print-access-token --impersonate-service-account="$SA_ANALYST" 2>/dev/null || true)"
  [ -n "$TOKEN" ] && break
  echo "  waiting for the impersonation grant to propagate (${attempt}/6)"
  sleep 15
done
if [ -z "$TOKEN" ]; then
  echo "FAIL: could not mint a token as analyst-sa after 90s" >&2
  exit 1
fi
CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries" \
  -d '{"query":"SELECT COUNT(*) FROM `'"$PROJECT"'.holdout_sealed.turns`","useLegacySql":false,"location":"'"$BQ_LOCATION"'"}')"
if [ "$CODE" != "403" ]; then
  echo "FAIL: analyst-sa was not refused the sealed holdout; got HTTP $CODE" >&2
  exit 1
fi
echo "verified: analyst-sa is refused the sealed holdout (HTTP 403)"

CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries" \
  -d '{"query":"DELETE FROM `'"$PROJECT"'.policy.versions` WHERE version = \"__never__\"","useLegacySql":false,"location":"'"$BQ_LOCATION"'"}')"
if [ "$CODE" != "403" ]; then
  echo "FAIL: analyst-sa was not refused a delete on the policy registry; got HTTP $CODE" >&2
  exit 1
fi
echo "verified: analyst-sa is refused a write to the policy registry (HTTP 403)"
