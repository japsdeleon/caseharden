#!/usr/bin/env bash
# Lock the retention policy. IRREVERSIBLE.
#
# Once locked, the retention period can be raised but never lowered or removed,
# and the bucket cannot be deleted until every object inside it has aged past
# retention. That is the whole point: an unlocked policy can be removed by the
# project owner before deleting, so only a locked one supports the claim that the
# record cannot be edited after the fact.
#
# Run deliberately. It refuses unless CASEHARDEN_CONFIRM_LOCK=LOCK is set.
set -euo pipefail
source "$(dirname "$0")/env.sh"

if [ "${CASEHARDEN_CONFIRM_LOCK:-}" != "LOCK" ]; then
  cat <<MSG
Refusing to lock without explicit confirmation.

  bucket     gs://${BUCKET}
  retention  $(gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" \
                --format="value(retention_policy.retentionPeriod)") seconds

Locking cannot be undone. The bucket cannot be deleted until every object in it
is older than the retention period. To proceed:

  CASEHARDEN_CONFIRM_LOCK=LOCK bash infra/62_lock_retention.sh
MSG
  exit 1
fi

# gcloud prompts here and --quiet answers its default, which is no. The guard above
# is this script's confirmation, so answer the prompt.
printf "y\n" | gcloud storage buckets update "gs://${BUCKET}" --lock-retention-period \
  --project="$PROJECT"

gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" \
  --format="yaml(name,retention_policy)"
