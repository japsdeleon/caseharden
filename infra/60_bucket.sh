#!/usr/bin/env bash
# The second platform-owned guarantee: a sealed certificate cannot be edited or
# deleted after the fact, including by the project owner.
#
# This script creates the bucket and sets the retention policy. It does NOT lock
# it. Locking is irreversible and is a separate, explicit step: 61_lock_retention.sh.
set -euo pipefail
source "$(dirname "$0")/env.sh"

RETENTION="${CASEHARDEN_RETENTION:-30d}"

if ! gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${BUCKET}" \
    --project="$PROJECT" \
    --location="$REGION" \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --default-storage-class=STANDARD
fi

gcloud storage buckets update "gs://${BUCKET}" \
  --retention-period="$RETENTION" --project="$PROJECT"

# The Notary is the only writer. It gets object create, not object delete.
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${SA_NOTARY}" --role=roles/storage.objectCreator \
  --project="$PROJECT" >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${SA_NOTARY}" --role=roles/storage.objectViewer \
  --project="$PROJECT" >/dev/null

gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" \
  --format="yaml(name,location,retention_policy,public_access_prevention,uniform_bucket_level_access)"
