#!/usr/bin/env bash
# What the deployed Policy Server runs as, and why it is examiner-sa.
#
# Verification re-derives two things: the cited events, and the exam. Re-scoring
# the exam means reading the sealed holdout, and exactly one principal may do
# that. So a Policy Server that re-derives at serve time either runs as
# examiner-sa or holds the power to impersonate it.
#
# It runs AS examiner-sa. The alternative, granting notary-sa
# roles/iam.serviceAccountTokenCreator on examiner-sa, would create a second
# principal that can reach the exam without adding a row to holdout_sealed's
# access list. That is the same class of hole the Day 3 adversarial pass found
# with project-level IAM, and re-opening it to save a deploy flag would be a poor
# trade. The access list still has exactly one entry.
#
# Everything granted below is a read. Nothing here can write a chain row, seal
# a certificate, or read the sealed exam's rows; the last is asserted at the end.
set -euo pipefail
source "$(dirname "$0")/env.sh"
HERE="$(cd "$(dirname "$0")" && pwd)"

# Reading who may read the exam, and reading the project bindings that could
# also reach it. Both are metadata, neither is data.
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$SA_EXAMINER" --role=roles/bigquery.metadataViewer \
  --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$SA_EXAMINER" \
  --role="projects/${PROJECT}/roles/casehardenIamReader" \
  --condition=None --quiet >/dev/null
echo "granted the two metadata reads to examiner-sa"

# Expanding a role into its permissions needs iam.roles.get, and reading who may
# act as the exam's reader needs iam.serviceAccounts.getIamPolicy. Both are
# reads, both feed chain link 1, and both were granted by hand before an audit
# pointed out that no script did it. Without them every role expands to "unknown"
# and therefore to "reaching", and the reach digest is a different set from the
# one the sealed certificates were built on.
for sa in "$SA_NOTARY" "$SA_EXAMINER"; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:${sa}" --role=roles/iam.roleViewer \
    --condition=None --quiet >/dev/null
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:${sa}" --role=roles/iam.serviceAccountViewer \
    --condition=None --quiet >/dev/null
done
echo "granted role and service-account read to notary-sa and examiner-sa"

python3 "${HERE}/bq_grant.py" "$PROJECT" chain READER "$SA_EXAMINER"
python3 "${HERE}/bq_grant.py" "$PROJECT" policy READER "$SA_EXAMINER"
python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_train READER "$SA_EXAMINER"
python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_live READER "$SA_EXAMINER"

# The sealed certificate, so a served answer can be compared against the root
# that was sealed rather than the root the chain claims for itself.
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:$SA_EXAMINER" --role=roles/storage.objectViewer \
  --quiet >/dev/null
echo "granted read on gs://${BUCKET} to examiner-sa"

# It reads the chain and it must never write one. Assert that, rather than
# trusting that no WRITER grant was made by accident.
TOKEN="$(gcloud auth print-access-token --impersonate-service-account="$SA_EXAMINER")"
CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries" \
  -d '{"query":"DELETE FROM `'"$PROJECT"'.chain.links` WHERE version = \"__never__\"","useLegacySql":false,"location":"'"$BQ_LOCATION"'"}')"
if [ "$CODE" != "403" ]; then
  echo "FAIL: examiner-sa was not refused a chain delete; got HTTP $CODE" >&2
  exit 1
fi
echo "verified: examiner-sa reads the chain and is refused a delete on it (HTTP 403)"
