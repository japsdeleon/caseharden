#!/usr/bin/env bash
# Five datasets and the role grants. The deny binding is separate, in 30_iam_deny.sh.
set -euo pipefail
source "$(dirname "$0")/env.sh"

mk() {
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" \
     mk --dataset --description="$2" "${PROJECT}:$1" 2>&1 | grep -v "already exists" || true
}

mk conduct_train  "Synthetic agent conduct events, days 1-76. The training window. Readable by the Proposer."
mk holdout_sealed "Labelled attack holdout, days 77-90. Read by examiner-sa only. proposer-sa is IAM-denied."
mk benign_corpus  "Legitimate tool-call turns. The benign side of the two-sided promotion gate."
mk chain          "Append-only hash-linked provenance chain."
mk policy         "Guardrail policy versions and their attestation state."

grant() { gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:$1" --role="$2" --condition=None --quiet >/dev/null; }

# Everyone who queries needs to run jobs.
for sa in "$SA_PROPOSER" "$SA_EXAMINER" "$SA_NOTARY" "$SA_FOREMAN" "$SA_WORKLOAD"; do
  grant "$sa" roles/bigquery.jobUser
done

# The Proposer holds an ordinary project-wide read. The deny binding in 30_iam_deny.sh
# carves holdout_sealed out of it. That ordering is the point: the 403 is a deny
# overriding a real grant, not the absence of one.
grant "$SA_PROPOSER" roles/bigquery.dataViewer
grant "$SA_EXAMINER" roles/bigquery.dataViewer
grant "$SA_FOREMAN"  roles/bigquery.dataViewer
grant "$SA_WORKLOAD" roles/bigquery.dataViewer

# The Notary is the only writer to the chain and the policy registry.
bq --project_id="$PROJECT" add-iam-policy-binding \
   --member="serviceAccount:$SA_NOTARY" --role=roles/bigquery.dataEditor \
   "${PROJECT}:chain" >/dev/null
bq --project_id="$PROJECT" add-iam-policy-binding \
   --member="serviceAccount:$SA_NOTARY" --role=roles/bigquery.dataEditor \
   "${PROJECT}:policy" >/dev/null

echo "Datasets and grants ready."
