#!/usr/bin/env bash
# Generate the corpora from the seed and load them. Idempotent: WRITE_TRUNCATE.
# Partitioned on the event date and clustered, so link-1 re-derivation prunes to
# the finding's window instead of scanning the warehouse.
set -euo pipefail
source "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python3 "$ROOT/generator/generate_conduct.py" --check
python3 "$ROOT/generator/generate_conduct.py" --out "$ROOT/out"

for ds in conduct_train holdout_sealed benign_corpus; do
  bq --project_id="$PROJECT" --location="$BQ_LOCATION" load \
    --source_format=NEWLINE_DELIMITED_JSON \
    --replace \
    --time_partitioning_field=ts \
    --time_partitioning_type=DAY \
    --clustering_fields=session_id,tenant_id,tool_name \
    "${PROJECT}:${ds}.turns" "$ROOT/out/${ds}.jsonl" "$ROOT/infra/schema_turns.json"
  echo "loaded ${ds}.turns"
done

bq --project_id="$PROJECT" query --nouse_legacy_sql --format=pretty \
"SELECT 'conduct_train' AS corpus, COUNT(*) AS events, COUNT(DISTINCT session_id) AS sessions FROM \`${PROJECT}.conduct_train.turns\`
 UNION ALL SELECT 'holdout_sealed', COUNT(*), COUNT(DISTINCT session_id) FROM \`${PROJECT}.holdout_sealed.turns\`
 UNION ALL SELECT 'benign_corpus', COUNT(*), COUNT(DISTINCT session_id) FROM \`${PROJECT}.benign_corpus.turns\`"
