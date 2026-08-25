#!/usr/bin/env bash
# The first of the two platform-owned guarantees: the Proposer cannot read its own exam.
#
# Why this is a dataset access list and not an IAM deny policy
# ------------------------------------------------------------
# An IAM deny policy would be the stronger artifact: a deny rule beats any grant,
# including one an owner adds later. It is not available here. Creating one needs
# iam.denypolicies.create, which lives only in roles/iam.denyAdmin, and that role
# cannot be bound at project scope:
#
#   ERROR: INVALID_ARGUMENT: Role roles/iam.denyAdmin is not supported for this resource.
#
# It binds at organization or folder scope, and this project has no parent. The
# permission is also rejected from custom roles:
#
#   ERROR: INVALID_ARGUMENT: Permission iam.denypolicies.create is not supported in custom roles.
#
# So the seal is built the other way round. No principal holds a project-wide
# BigQuery read (20_bigquery.sh), the holdout's inherited projectReaders and
# projectWriters entries are stripped, and exactly one service account is granted
# it. The refusal is still BigQuery's, the audit log still names
# bigquery.tables.getData as denied, and the access list is three lines a reviewer
# can read. What is lost is that a future owner-level grant would not be overridden.
set -euo pipefail
source "$(dirname "$0")/env.sh"
HERE="$(dirname "$0")"

# Read access, per dataset. The Proposer gets the training window and the benign
# corpus. It is not on the holdout's list.
python3 "$HERE/bq_grant.py" "$PROJECT" conduct_train  READER "$SA_PROPOSER" "$SA_EXAMINER" "$SA_FOREMAN"
python3 "$HERE/bq_grant.py" "$PROJECT" benign_corpus  READER "$SA_PROPOSER" "$SA_EXAMINER"
python3 "$HERE/bq_grant.py" "$PROJECT" holdout_sealed READER "$SA_EXAMINER"
python3 "$HERE/bq_grant.py" "$PROJECT" chain          WRITER "$SA_NOTARY"
python3 "$HERE/bq_grant.py" "$PROJECT" policy         WRITER "$SA_NOTARY"

# A new dataset inherits projectReaders and projectWriters, which means anyone
# holding a project-level BigQuery role. A holdout that inherits those is not sealed.
python3 "$HERE/bq_seal_dataset.py" "$PROJECT" holdout_sealed

echo
echo "holdout_sealed access list:"
bq --project_id="$PROJECT" show --format=prettyjson "${PROJECT}:holdout_sealed" \
 | python3 -c "import json,sys; [print(f\"  {a.get('role'):<6} {a.get('userByEmail') or a.get('specialGroup') or a.get('groupByEmail')}\") for a in json.load(sys.stdin).get('access',[])]"
