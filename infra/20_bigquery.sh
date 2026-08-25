#!/usr/bin/env bash
# Five datasets, and job-running rights only. Read access is granted per dataset
# in 30_seal_holdout.sh, never project-wide.
set -euo pipefail
source "$(dirname "$0")/env.sh"

mk() {
  local out
  out="$(bq --project_id="$PROJECT" --location="$BQ_LOCATION" \
           mk --dataset --description="$2" "${PROJECT}:$1" 2>&1)" && { echo "created $1"; return 0; }
  # Only "already exists" is an acceptable failure. Anything else used to be
  # swallowed by `|| true`, and the success line printed anyway.
  # bq hard-wraps its error text, so "already exists" can arrive split across a
  # newline. Collapse whitespace before matching or the check silently fails.
  out="$(printf '%s' "$out" | tr '\n' ' ' | tr -s ' ')"
  case "$out" in
    *"already exists"*) echo "exists  $1" ;;
    *) echo "$out" >&2; return 1 ;;
  esac
}

mk conduct_train  "Synthetic agent conduct events, days 1-76. The training window. Readable by the Proposer."
mk holdout_sealed "Labelled attack holdout, days 77-90. examiner-sa is the only reader."
mk benign_corpus  "Legitimate tool-call turns. The benign side of the two-sided promotion gate."
mk chain          "Append-only hash-linked provenance chain."
mk policy         "Guardrail policy versions and their attestation state."

# Running a query and reading a table are separate permissions. Every principal
# needs the first. None of them gets the second at project scope, because a
# project-wide reader is a reader of the holdout too.
for sa in "$SA_PROPOSER" "$SA_EXAMINER" "$SA_NOTARY" "$SA_FOREMAN" "$SA_WORKLOAD"; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:$sa" --role=roles/bigquery.jobUser \
    --condition=None --quiet >/dev/null
done

# Assert the security claim rather than printing it. A project-wide dataViewer
# would reach the sealed holdout, so this is checked, not stated.
WIDE="$(gcloud projects get-iam-policy "$PROJECT" --format=json \
        | python3 -c "
import json, sys
policy = json.load(sys.stdin)
bad = [b['role'] for b in policy.get('bindings', [])
       if b['role'] in ('roles/bigquery.dataViewer', 'roles/bigquery.dataEditor',
                        'roles/bigquery.dataOwner', 'roles/bigquery.admin')]
print(','.join(bad))
")"
if [ -n "$WIDE" ]; then
  echo "FAIL: project-wide BigQuery data roles are bound: $WIDE" >&2
  exit 1
fi
echo "Datasets ready. Verified: no project-wide BigQuery data role is bound."
