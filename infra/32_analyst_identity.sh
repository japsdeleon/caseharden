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
