#!/usr/bin/env bash
# The first of the two platform-owned guarantees: the Proposer cannot read its
# own exam. Runs AFTER 30_load_corpora.sh, because sealing the dataset removes
# the operator's own write access to it.
#
# Why this is an access list and not an IAM deny policy
# -----------------------------------------------------
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
# So the seal is built the other way. No principal holds a project-wide BigQuery
# data role (asserted in 20_bigquery.sh), and holdout_sealed's access list is
# reduced to exactly one entry: examiner-sa as its owner. BigQuery requires every
# dataset to keep an owner, so the exam is owned by the one principal meant to
# read it rather than left as a reader beside inherited project owners.
#
# The result is stronger than the plan asked for. bigquery.tables.getData is not
# part of roles/owner, so the human project owner is refused this dataset too.
# What a deny policy would still add is protection against a future grant.
set -euo pipefail
source "$(dirname "$0")/env.sh"
HERE="$(dirname "$0")"

# Read access, per dataset. The Proposer gets the training window and the benign
# corpus. It is not on the holdout's list.
# The Notary is a reader of the conduct events because re-deriving link 1 means
# re-scanning them. It is not a reader of the exam, and never becomes one: it
# reads holdout_sealed's access list through project-scoped metadataViewer,
# granted in 25_chain_tables.sh, which does not carry tables.getData.
python3 "$HERE/bq_grant.py" "$PROJECT" conduct_train  READER "$SA_PROPOSER" "$SA_EXAMINER" "$SA_FOREMAN" "$SA_NOTARY"
python3 "$HERE/bq_grant.py" "$PROJECT" benign_corpus  READER "$SA_PROPOSER" "$SA_EXAMINER"
# The workload agent writes one conduct event per turn it takes. It is the only
# writer of the event stream, and it cannot read the stream back.
python3 "$HERE/bq_grant.py" "$PROJECT" conduct_train  WRITER "$SA_WORKLOAD"
python3 "$HERE/bq_grant.py" "$PROJECT" chain          WRITER "$SA_NOTARY"
python3 "$HERE/bq_grant.py" "$PROJECT" policy         WRITER "$SA_NOTARY"

# The exam: one entry, and it is the Examiner.
python3 "$HERE/bq_seal_dataset.py" "$PROJECT" holdout_sealed --sole-owner "$SA_EXAMINER"

# The chain and the policy registry keep their owners but lose projectWriters.
# roles/editor is held by the compute default service account, which Cloud Run
# uses when no service account is named, so an inherited projectWriters entry
# makes the append-only chain writable by anything deployed carelessly on Day 4.
python3 "$HERE/bq_seal_dataset.py" "$PROJECT" chain
python3 "$HERE/bq_seal_dataset.py" "$PROJECT" policy
python3 "$HERE/bq_seal_dataset.py" "$PROJECT" conduct_train
python3 "$HERE/bq_seal_dataset.py" "$PROJECT" benign_corpus

echo
echo "holdout_sealed access list:"
bq --project_id="$PROJECT" show --format=prettyjson "${PROJECT}:holdout_sealed" \
 | python3 -c "import json,sys; [print(f\"  {a.get('role'):<6} {a.get('userByEmail') or a.get('specialGroup') or a.get('groupByEmail')}\") for a in json.load(sys.stdin).get('access',[])]"
