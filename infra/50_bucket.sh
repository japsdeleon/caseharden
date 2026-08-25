#!/usr/bin/env bash
# The second platform-owned guarantee: a sealed certificate cannot be edited or
# deleted after the fact, including by the project owner.
#
# This script creates the bucket and sets the retention policy. It does NOT lock
# it. Locking is irreversible and is a separate, explicit step: 60_lock_retention.sh.
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

# Setting the same period again is refused once the policy is locked, and that
# refusal is expected rather than an error.
if [ "$(gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" \
        --format='value(retention_policy.isLocked)')" = "True" ]; then
  echo "retention policy already locked; leaving it alone"
else
  gcloud storage buckets update "gs://${BUCKET}" \
    --retention-period="$RETENTION" --project="$PROJECT"
fi

# The Notary is the only writer. It gets object create and read, not delete.
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${SA_NOTARY}" --role=roles/storage.objectCreator \
  --project="$PROJECT" >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${SA_NOTARY}" --role=roles/storage.objectViewer \
  --project="$PROJECT" >/dev/null

# A new bucket carries legacy bindings that hand every project editor
# storage.objects.create, storage.objects.delete, storage.objects.setRetention
# and storage.buckets.setIamPolicy. The compute default service account holds
# roles/editor and is what Cloud Run uses when no service account is named, so
# leaving these makes "the Notary is the only writer" false the moment anything
# is deployed carelessly. Project owners keep theirs, or this is unrecoverable.
for role in roles/storage.legacyBucketOwner roles/storage.legacyObjectOwner; do
  gcloud storage buckets remove-iam-policy-binding "gs://${BUCKET}" \
    --member="projectEditor:${PROJECT}" --role="$role" \
    --project="$PROJECT" >/dev/null 2>&1 && echo "removed ${role} from projectEditor"
done

gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" \
  --format="yaml(name,location,retention_policy,public_access_prevention,uniform_bucket_level_access)"
