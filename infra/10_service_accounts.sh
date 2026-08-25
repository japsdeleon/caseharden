#!/usr/bin/env bash
# Five service accounts, one per role. Idempotent.
set -euo pipefail
source "$(dirname "$0")/env.sh"

create() {
  local id="$1" name="$2" desc="$3"
  gcloud iam service-accounts describe "${id}@${PROJECT}.iam.gserviceaccount.com" \
    --project="$PROJECT" >/dev/null 2>&1 && { echo "exists: $id"; return 0; }
  gcloud iam service-accounts create "$id" \
    --display-name="$name" --description="$desc" --project="$PROJECT"
}

create proposer-sa "Caseharden Proposer" \
  "Drafts guardrail candidates. Reads the training window only. IAM-denied on the sealed holdout."
create examiner-sa "Caseharden Examiner" \
  "Deterministic scorer. The only principal with read access to the sealed holdout."
create notary-sa   "Caseharden Notary" \
  "Writes hash-linked chain rows and seals certificates into the retention-locked bucket."
create foreman-sa  "Caseharden Foreman" \
  "Orchestrator. Discovers detectors through Agent Registry and fans investigations out over A2A."
create workload-sa "Caseharden Workload Agent" \
  "The governed support agent and the attack target."

echo "Service accounts ready."
