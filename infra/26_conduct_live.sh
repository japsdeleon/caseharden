#!/usr/bin/env bash
# The live conduct table, and the identity the detectors read it with.
#
# Live events are NOT written into conduct_train.turns. Chain link 1 hashes each
# cited row as SHA256(TO_JSON_STRING(t)), and TO_JSON_STRING emits a key for
# every column including null ones, so adding this table's four decision columns
# to conduct_train would change the digest of every row already cited and
# quarantine every chain in the project at once. That behaviour is correct, a
# schema change under a cited window really is an evidence change, but it is not
# something to trigger by accident. Verified in this project:
#   SELECT TO_JSON_STRING(t) FROM (SELECT 1 AS a, CAST(NULL AS STRING) AS b) t
#   -> {"a":1,"b":null}
#
# The two answer-key columns, label and is_attack_event, are absent by design.
# Live traffic has no ground truth, so a column for it could only ever be filled
# in by guessing.
set -euo pipefail
source "$(dirname "$0")/env.sh"
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! bq --project_id="$PROJECT" show "${PROJECT}:conduct_live" >/dev/null 2>&1; then
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" mk --dataset \
     --description="Live conduct events written by the fleet's enforcement callback." \
     "${PROJECT}:conduct_live" >/dev/null
  echo "created dataset conduct_live"
else
  echo "exists  dataset conduct_live"
fi

if ! bq --project_id="$PROJECT" show "${PROJECT}:conduct_live.turns" >/dev/null 2>&1; then
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" mk --table \
     --time_partitioning_field=ts --time_partitioning_type=DAY \
     --clustering_fields=session_id,tool_name \
     "${PROJECT}:conduct_live.turns" "${HERE}/schema_turns_live.json" >/dev/null
  echo "created conduct_live.turns"
else
  echo "exists  conduct_live.turns"
fi

# One identity for the four detectors. They share it because they are one
# template with four parameter sets, and a per-family service account would
# claim an isolation the code does not have.
if ! gcloud iam service-accounts describe "$SA_DETECTOR" >/dev/null 2>&1; then
  gcloud iam service-accounts create detector-sa \
    --display-name="Caseharden detectors" \
    --description="Reads conduct. Refused the sealed holdout." --quiet >/dev/null
  echo "created detector-sa"
else
  echo "exists  detector-sa"
fi

gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$SA_DETECTOR" --role=roles/bigquery.jobUser \
  --condition=None --quiet >/dev/null

python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_live READER "$SA_DETECTOR"
python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_train READER "$SA_DETECTOR"
python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_live WRITER "$SA_WORKLOAD"
python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_live READER "$SA_FOREMAN"
python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_live READER "$SA_PROPOSER"
# The Notary reads this table because a chain whose finding came from the live
# stream cites the live stream, and verification re-scans the cited window as
# notary-sa. Without it every such chain verifies as unknown, which reads as an
# outage rather than as a missing grant. Dataset-scoped: a project-level read
# would put another principal within reach of the sealed exam's neighbourhood
# and would change the reach digest every chain in the project is sealed on.
python3 "${HERE}/bq_grant.py" "$PROJECT" conduct_live READER "$SA_NOTARY"
echo "granted conduct_live and conduct_train reads"

# The seal covers every identity, not just the Proposer's. A detector that could
# read the exam would make the gate scoreable from inside the fleet.
TOKEN="$(gcloud auth print-access-token --impersonate-service-account="$SA_DETECTOR")"
CODE="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -X POST "https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries" \
  -d '{"query":"SELECT COUNT(*) FROM `'"$PROJECT"'.holdout_sealed.turns`","useLegacySql":false,"location":"'"$BQ_LOCATION"'"}')"
if [ "$CODE" != "403" ]; then
  echo "FAIL: detector-sa was not refused the sealed holdout; got HTTP $CODE" >&2
  exit 1
fi
echo "verified: detector-sa is refused the sealed holdout (HTTP 403)"
