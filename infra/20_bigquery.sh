#!/usr/bin/env bash
# Five datasets, and job-running rights only. Read access is granted per dataset
# in 30_seal_holdout.sh, never project-wide.
set -euo pipefail
source "$(dirname "$0")/env.sh"

mk() {
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" \
     mk --dataset --description="$2" "${PROJECT}:$1" 2>&1 | grep -v "already exists" || true
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

echo "Datasets created. No principal holds a project-wide BigQuery read."
