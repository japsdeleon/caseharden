#!/usr/bin/env bash
# Add the policy line column to the registry and claim the existing rows for
# conduct-policy. THREATS.md entry 11: the registry and the serving layer are
# line-aware and nothing else is.
#
# policy.versions is registry metadata. No chain link hashes it, so this ALTER
# moves no attestation — unlike a column on the conduct table, which THREATS.md
# entry 10 exists for. Run once; both statements are safe to re-run.
set -euo pipefail

PROJECT="${CASEHARDEN_PROJECT:-devpost-hackathon-506416}"
BQ_LOCATION="${CASEHARDEN_BQ_LOCATION:-europe-west3}"

bq --project_id="$PROJECT" --location="$BQ_LOCATION" query \
   --use_legacy_sql=false --quiet >/dev/null <<SQL
ALTER TABLE \`${PROJECT}.policy.versions\`
  ADD COLUMN IF NOT EXISTS policy_id STRING
SQL
echo "policy.versions carries policy_id"

bq --project_id="$PROJECT" --location="$BQ_LOCATION" query \
   --use_legacy_sql=false --quiet >/dev/null <<SQL
UPDATE \`${PROJECT}.policy.versions\`
  SET policy_id = 'conduct-policy'
  WHERE policy_id IS NULL
SQL
echo "existing rows claimed for conduct-policy"
