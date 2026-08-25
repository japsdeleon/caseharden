#!/usr/bin/env bash
# Six service accounts, one per role. Idempotent.
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
create detector-sa "Caseharden Detectors" \
  "One identity for the four conduct checks. Reads conduct, refused the sealed holdout."

echo "Service accounts ready."

# The proofs in 70_ and 71_ act as these principals through impersonation.
# roles/owner does not carry iam.serviceAccounts.getAccessToken, so without this
# grant 70_prove_seal.sh cannot mint a token and exits before proving anything.
OPERATOR="${CASEHARDEN_OPERATOR:-$(gcloud config get-value account 2>/dev/null)}"
# workload-sa is here because it writes the conduct event stream, and the Day 3
# tamper is one ordinary late event arriving from that same writer. foreman-sa
# and detector-sa joined on Day 4, when the fleet proof began acting as each of
# them to show what the fleet's own identities can and cannot reach.
for sa in "$SA_PROPOSER" "$SA_EXAMINER" "$SA_NOTARY" "$SA_WORKLOAD" \
          "$SA_FOREMAN" "$SA_DETECTOR"; do
  gcloud iam service-accounts add-iam-policy-binding "$sa" \
    --member="user:${OPERATOR}" --role=roles/iam.serviceAccountTokenCreator \
    --project="$PROJECT" --quiet >/dev/null
done
echo "Impersonation granted to ${OPERATOR} on the six audited principals."
