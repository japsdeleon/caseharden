#!/usr/bin/env bash
# The append-only chain and the policy registry.
#
# "Append-only" is a convention on this table, not a platform guarantee: WRITER
# on the dataset carries DML delete, and BigQuery has no append-only table mode.
# What makes an edit detectable is that each promotion's root is sealed into the
# retention-locked bucket, which refuses a delete from the project owner. A chain
# rewritten in place, hashes and all, still disagrees with its certificate.
# THREATS.md carries this rather than the README claiming immutability BigQuery
# does not provide.
set -euo pipefail
source "$(dirname "$0")/env.sh"

mk() {
  local table="$1" schema="$2" extra="${3:-}"
  if bq --project_id="$PROJECT" show "${PROJECT}:${table}" >/dev/null 2>&1; then
    echo "exists  $table"
    return 0
  fi
  # shellcheck disable=SC2086
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" mk --table $extra \
     "${PROJECT}:${table}" "$schema" >/dev/null
  echo "created $table"
}

# Partitioned on the write date and clustered on version, so reading one
# version's chain does not scan every version ever promoted.
mk chain.links \
  "version:STRING,seq:INTEGER,kind:STRING,written_at:TIMESTAMP,prev_hash:STRING,link_hash:STRING,payload:STRING" \
  "--time_partitioning_field=written_at --time_partitioning_type=DAY --clustering_fields=version,seq"

mk policy.versions \
  "version:STRING,parent:STRING,policy:STRING,active:BOOLEAN,root:STRING,certificate_uri:STRING,promoted_at:TIMESTAMP"

# The Notary must be able to read WHO may read the sealed exam without being
# able to read the exam. roles/bigquery.metadataViewer carries datasets.get and
# tables.get and does not carry tables.getData, so link 1 can hash the access
# list and the 403 in the same chain stays a real 403.
#
# Bound at project scope on purpose. A dataset-scoped grant would add a second
# entry to holdout_sealed's access list, and that list having exactly one entry
# is the artifact a reviewer opens.
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$SA_NOTARY" --role=roles/bigquery.metadataViewer \
  --condition=None --quiet >/dev/null
echo "granted roles/bigquery.metadataViewer to notary-sa at project scope"

# A finding names the BigQuery job that produced it, and the Notary refuses to
# write a chain citing a job it cannot see. The detectors run those jobs as
# detector-sa, and jobs.get on somebody else's job needs a project-level role.
# roles/bigquery.resourceViewer carries jobs.get and jobs.list and does NOT
# carry bigquery.tables.getData, so it does not put the Notary within reach of
# the sealed exam and does not change the reach digest every certificate is
# sealed on. Checked with the same expansion `verify` uses, not assumed.
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$SA_NOTARY" --role=roles/bigquery.resourceViewer \
  --condition=None --quiet >/dev/null
echo "granted roles/bigquery.resourceViewer to notary-sa, so it can see the jobs it cites"

# A dataset access list is not the only way to reach a table. A project-level
# IAM binding grants the same permission and never appears in that list, so
# hashing the list alone left the easier of the two grants unnoticed. Link 1
# hashes both, which means the Notary has to be able to read the project's IAM
# policy. One permission, in a custom role, and it reads no data.
ROLE_ID="casehardenIamReader"
if ! gcloud iam roles describe "$ROLE_ID" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud iam roles create "$ROLE_ID" --project="$PROJECT" \
    --title="Caseharden IAM reader" \
    --description="Read the project IAM policy, so the chain can hash who could reach the sealed exam." \
    --permissions=resourcemanager.projects.getIamPolicy \
    --stage=GA --quiet >/dev/null
  echo "created custom role $ROLE_ID"
else
  echo "exists  custom role $ROLE_ID"
fi
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$SA_NOTARY" --role="projects/${PROJECT}/roles/${ROLE_ID}" \
  --condition=None --quiet >/dev/null
echo "granted projects/${PROJECT}/roles/${ROLE_ID} to notary-sa"

# Assert it, rather than trusting the role description. The Notary reading the
# access list and still being refused the rows is the property link 1 rests on.
TOKEN="$(gcloud auth print-access-token --impersonate-service-account="$SA_NOTARY")"
if bq --project_id="$PROJECT" show --format=prettyjson "${PROJECT}:holdout_sealed" >/dev/null 2>&1; then
  :
fi
CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries" \
  -d '{"query":"SELECT COUNT(*) FROM `'"$PROJECT"'.holdout_sealed.turns`","useLegacySql":false,"location":"'"$BQ_LOCATION"'"}')"
if [ "$CODE" != "403" ]; then
  echo "FAIL: notary-sa was not refused the sealed holdout; got HTTP $CODE" >&2
  exit 1
fi
echo "verified: notary-sa reads the access list and is refused the rows (HTTP 403)"
