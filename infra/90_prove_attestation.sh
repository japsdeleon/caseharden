#!/usr/bin/env bash
# Day 3 exit criterion, asserted rather than narrated:
#
#   green -> quarantine -> promotion refused -> re-attest -> green again
#
# plus the two properties that sequence rests on: the Policy Server reports the
# live state to the fleet, and the sealed certificate cannot be deleted.
#
# Every assertion is on real output from the real project. The script exits
# non-zero the moment one of them changes.
#
# Re-running it: a streamed row cannot be removed by DML for about 90 minutes,
# so the tamper is one-way within a rehearsal. The script picks a fresh event id
# when the default one is already in the cited window, which makes the run
# repeatable without pretending the previous tamper was undone.
set -euo pipefail
source "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-v4}"
CANDIDATE="${CANDIDATE:-policies/v4-candidate-b.json}"
PORT="${PORT:-8099}"

want() {  # want <needle> <file> <what failed>
  grep -qF -- "$1" "$2" || { echo "FAIL: $3 (expected: $1)" >&2; exit 1; }
}
code() {  # code <expected> <actual> <what failed>
  [ "$1" = "$2" ] || { echo "FAIL: $3 (expected exit $1, got $2)" >&2; exit 1; }
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; kill %1 2>/dev/null || true' EXIT

echo "=============================================================="
echo " 1. A promoted version re-derives from raw evidence"
echo "=============================================================="
PARENT="${PARENT:-v3}"
if ! python3 -m caseharden.notary verify --version "$VERSION" >/dev/null 2>&1; then
  # The parent has to be a version, not a name. Registering the genesis is what
  # makes a first promotion legitimate and `--parent v99` a refusal.
  python3 -m caseharden.notary genesis --version "$PARENT" \
    --policy policies/v3-active.json 2>/dev/null || true
  python3 -m caseharden.notary seed --version "$VERSION" --parent "$PARENT" --candidate "$CANDIDATE"
fi
set +e; python3 -m caseharden.notary verify --version "$VERSION" | tee "$TMP/green.txt"; RC=${PIPESTATUS[0]}; set -e
code 0 "$RC" "a freshly sealed version did not attest"
want "ATTESTED" "$TMP/green.txt" "the version did not report ATTESTED"
want "[1] EVIDENCE" "$TMP/green.txt" "link 1 is not the evidence link"
want "readable by 1 principal(s)" "$TMP/green.txt" "the exam has more than one reader"
# The exam leg is the entry's central claim and was asserted nowhere: every other
# string in this step is still present on a chain whose Examiner is never re-run.
want "the Examiner re-scores" "$TMP/green.txt" "the exam was not re-derived"
want "re-derived" "$TMP/green.txt" "no link reports a re-derivation"

set +e
python3 -m caseharden.notary verify --version "$VERSION" --json > "$TMP/green.json"
set -e
python3 - "$TMP/green.json" <<'PY'
import json, sys
att = json.load(open(sys.argv[1]))
derived = {l["kind"] for l in att["links"] if l["mode"] == "re-derived"}
assert "EXAM" in derived or "EVIDENCE-CHANGED" in derived, \
    f"no exam link was re-derived; re-derived kinds were {sorted(derived)}"
assert any(k in derived for k in ("EVIDENCE", "EVIDENCE-CHANGED")), \
    "no evidence link was re-derived"
print(f"re-derived: {', '.join(sorted(derived))}; recorded only: "
      f"{', '.join(sorted({l['kind'] for l in att['links'] if l['mode'] == 'recorded'}))}")
PY

echo
echo "\$ notary promote --version v6 --parent v99   (a name that is not a version)"
set +e
python3 -m caseharden.notary promote --version v6 --parent v99 --candidate "$CANDIDATE" \
  > "$TMP/unknown-parent.txt" 2>&1
RC=$?
set -e
cat "$TMP/unknown-parent.txt"
code 5 "$RC" "a promotion onto a name that was never a version was not refused"
want "is not a version of this policy" "$TMP/unknown-parent.txt" "wrong refusal for an unknown parent"

echo
echo "=============================================================="
echo " 2. The fleet is told the live state, not a stored one"
echo "=============================================================="
python3 -m caseharden.policy_server --port "$PORT" > "$TMP/server.log" 2>&1 &
for _ in $(seq 1 30); do
  curl -sf --max-time 5 "localhost:${PORT}/healthz" >/dev/null && break
  sleep 1
done
curl -sf --max-time 60 "localhost:${PORT}/healthz" >/dev/null || {
  echo "FAIL: the Policy Server did not come up on :${PORT}" >&2
  cat "$TMP/server.log" >&2; exit 1; }
# The first request mints two impersonated tokens and runs a full verification.
curl -s --max-time 90 "localhost:${PORT}/policy/${VERSION}" > "$TMP/serve-green.json"
want '"state": "ATTESTED"' "$TMP/serve-green.json" "the Policy Server did not serve ATTESTED"
want '"promotions": "OPEN"' "$TMP/serve-green.json" "promotions were not open on a green version"
python3 -c "
import json;d=json.load(open('$TMP/serve-green.json'))
print(f\"served {d['version']}: {d['state']}, promotions {d['promotions']}, \"
      f\"{len(d['links'])} links, verify took {d['verify_seconds']}s\")"

echo
echo "=============================================================="
echo " 3. One ordinary late event, and the version loses its standing"
echo "=============================================================="
# A streamed row is permanent for the length of a rehearsal, so a re-run has to
# tamper with an id the window does not already carry. Asked of the table, not
# of verify: verify prints link summaries, not the event ids behind them.
EVENT_ID="${EVENT_ID:-e_88214}"
if python3 - "$EVENT_ID" <<'PY'
import os, sys
sys.path.insert(0, ".")
from caseharden import bq
project = os.environ["PROJECT"]
token = bq.access_token(f"notary-sa@{project}.iam.gserviceaccount.com")
rows = bq.query(
    f"SELECT COUNT(*) n FROM `{project}.conduct_train.turns` WHERE event_id = @id",
    project, token, params={"id": sys.argv[1]})
sys.exit(0 if int(rows[0]["n"]) else 1)
PY
then
  EVENT_ID="e_late_$(date +%s)"
  echo "note: the default event id is already in the window; using $EVENT_ID"
fi
python3 infra/tamper.py --event-id "$EVENT_ID"
sleep 3
set +e; python3 -m caseharden.notary verify --version "$VERSION" | tee "$TMP/broken.txt"; RC=${PIPESTATUS[0]}; set -e
code 6 "$RC" "a tampered window did not quarantine"
want "QUARANTINED" "$TMP/broken.txt" "the version was not quarantined"
want "EVENT-WINDOW" "$TMP/broken.txt" "the break was not attributed to the event window"
want "$EVENT_ID" "$TMP/broken.txt" "the break did not name the offending event"
want "promotions FROZEN" "$TMP/broken.txt" "promotions were not frozen"

curl -s --max-time 90 "localhost:${PORT}/policy/${VERSION}" > "$TMP/serve-broken.json"
if grep -qF '"cached": true' "$TMP/serve-broken.json"; then
  echo "note: served from the 60s cache, as designed; waiting it out"
  sleep 62
  curl -s --max-time 90 "localhost:${PORT}/policy/${VERSION}" > "$TMP/serve-broken.json"
fi
want '"state": "QUARANTINED"' "$TMP/serve-broken.json" "the Policy Server did not serve QUARANTINED"
want '"promotions": "FROZEN"' "$TMP/serve-broken.json" "the Policy Server left promotions open"
want '"attested": false' "$TMP/serve-broken.json" "the Policy Server still called the version attested"

echo
echo "=============================================================="
echo " 4. Nothing may be promoted on top of an unattested version"
echo "=============================================================="
set +e
python3 -m caseharden.notary promote --version v5 --parent "$VERSION" \
  --candidate "$CANDIDATE" > "$TMP/refused.txt" 2>&1
RC=$?
set -e
cat "$TMP/refused.txt"
code 5 "$RC" "a promotion onto a quarantined parent was not refused"
want "REFUSED — cannot build on an unattested version" "$TMP/refused.txt" "wrong refusal"
want "nothing was written to the chain" "$TMP/refused.txt" "the refusal did not say the chain was untouched"

echo
echo "=============================================================="
echo " 5. The remedy is re-derivation, and it is not an undo"
echo "=============================================================="
set +e; python3 -m caseharden.notary reattest --version "$VERSION" | tee "$TMP/reattest.txt"; RC=${PIPESTATUS[0]}; set -e
code 0 "$RC" "re-attestation did not return the version to green"
want "RE-ATTESTED" "$TMP/reattest.txt" "the re-attestation was refused"
want "EVIDENCE-CHANGED" "$TMP/reattest.txt" "no evidence-change link was appended"
want "restated by link" "$TMP/reattest.txt" "the original evidence link was not marked superseded"
want "ATTESTED   re-derived" "$TMP/reattest.txt" "the version did not go green again"
# The remedy must not switch the central claim off. Re-deriving only the evidence
# half of the superseding link left the exam unchecked from here onward.
want "the Examiner re-scores" "$TMP/reattest.txt" "the exam was not re-derived after re-attestation"

# The record was superseded, not edited. The original link is still link 1 and
# still carries the digest it carried at promotion.
python3 - "$VERSION" <<'PY'
import subprocess, sys, json, os
sys.path.insert(0, ".")
from caseharden import bq, chain
version = sys.argv[1]
project = os.environ["PROJECT"]
token = bq.access_token(f"notary-sa@{project}.iam.gserviceaccount.com")
links = chain.ChainStore(project, token).read(version)
stated = [l for l in links if l.kind in ("EVIDENCE", "EVIDENCE-CHANGED")]
first, last = stated[0], stated[-1]
assert first.seq == 1 and first.kind == "EVIDENCE", "the original evidence link moved"
assert first.payload["event_digest"] != last.payload["event_digest"], \
    "the superseding link carries the same evidence digest"
# Each re-attestation supersedes the evidence statement in force at the time,
# which is link 1 on the first run and the previous EVIDENCE-CHANGED after that.
assert last.payload["supersedes"] == stated[-2].seq, "the wrong link was superseded"
assert all(l.intact() for l in stated), "an evidence link was rewritten in place"
print(f"link 1 still hashes to {first.hash[:12]} and still cites "
      f"{first.payload['row_count']} events; link {last.seq} cites "
      f"{last.payload['row_count']}")
PY

echo
echo "=============================================================="
echo " 6. Promotion is open again, and the certificate cannot be deleted"
echo "=============================================================="
set +e
python3 -m caseharden.notary promote --version v5 --parent "$VERSION" --candidate "$CANDIDATE" \
  > "$TMP/allowed.txt" 2>&1
RC=$?
set -e
cat "$TMP/allowed.txt"
code 0 "$RC" "promotion was still refused after a successful re-attestation"
want "parent accepted" "$TMP/allowed.txt" "the parent was not accepted"

URI="$(python3 - "$VERSION" <<'PY'
import os, sys
sys.path.insert(0, ".")
from caseharden import bq, chain
project = os.environ["PROJECT"]
token = bq.access_token(f"notary-sa@{project}.iam.gserviceaccount.com")
rows = [r for r in chain.ChainStore(project, token).versions() if r["version"] == sys.argv[1]]
print(rows[0]["certificate_uri"])
PY
)"
# Asked of the JSON API rather than `gcloud storage rm`, which reports this
# refusal as GcsApiError('') and hides the reason. The point of the assertion is
# the reason: refused BY THE RETENTION POLICY, not by a missing permission. The
# token is the operator's own, so this is the project owner being told no.
OBJ="${URI#gs://${BUCKET}/}"
ENCODED="$(python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=''))" "$OBJ")"
DEL="$(curl -s -X DELETE \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${ENCODED}")"
echo "$DEL" | grep -q "retentionPolicyNotMet" || {
  echo "FAIL: the sealed certificate was not refused deletion by the retention policy" >&2
  echo "$DEL" >&2; exit 1; }
echo "\$ DELETE storage/v1/b/${BUCKET}/o/${OBJ}   (as the project owner)"
echo "$DEL" | python3 -c "
import json, sys
err = json.load(sys.stdin)['error']['errors'][0]
print(f\"  refused: {err['reason']} - {err['message']}\")"

python3 -m caseharden.notary certificate --version "$VERSION" --out "out/certificate-${VERSION}.html"

echo
echo "=============================================================="
echo " ALL SIX HELD."
echo "=============================================================="
