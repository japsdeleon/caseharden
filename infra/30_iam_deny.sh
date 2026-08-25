#!/usr/bin/env bash
# The first of the two platform-owned guarantees: the Proposer cannot read its own exam.
#
# proposer-sa already holds roles/bigquery.dataViewer project-wide (20_bigquery.sh).
# This deny policy carves holdout_sealed out of that grant. A deny rule beats any
# grant, including one an Owner adds later, so the 403 is a property of Google's
# authorization layer rather than of this project's code.
set -euo pipefail
source "$(dirname "$0")/env.sh"

POLICY_ID="caseharden-holdout-seal"
ATTACH="cloudresourcemanager.googleapis.com%2Fprojects%2F${PROJECT}"
TMP="$(mktemp -d)/deny.yaml"

cat > "$TMP" <<YAML
displayName: "Caseharden: the Proposer may not read the sealed holdout"
rules:
- denyRule:
    deniedPrincipals:
    - principal://iam.googleapis.com/projects/-/serviceAccounts/${SA_PROPOSER}
    deniedPermissions:
    - bigquery.googleapis.com/tables.getData
    - bigquery.googleapis.com/tables.get
    - bigquery.googleapis.com/tables.list
    denialCondition:
      title: sealed-holdout-only
      description: "Applies only to the holdout_sealed dataset. Every other dataset is unaffected."
      expression: |
        resource.name.startsWith("projects/${PROJECT}/datasets/holdout_sealed")
YAML

echo "--- deny policy ---"; cat "$TMP"

gcloud iam policies create "$POLICY_ID" \
  --attachment-point="$ATTACH" \
  --kind=denypolicies \
  --policy-file="$TMP"

# examiner-sa is the only principal granted the holdout. Nothing denies it.
bq --project_id="$PROJECT" add-iam-policy-binding \
   --member="serviceAccount:$SA_EXAMINER" --role=roles/bigquery.dataViewer \
   "${PROJECT}:holdout_sealed" >/dev/null

echo "Deny policy ${POLICY_ID} attached to ${PROJECT}."
