#!/usr/bin/env bash
# Exit criterion 2: a sealed certificate can be neither deleted nor overwritten,
# and the refusal comes from Cloud Storage rather than from any code here.
#
# Both attempts are made as the project OWNER on purpose. Owner is the strongest
# principal available in this project, and the retention policy refuses it anyway.
#
# gcloud reports the refusal as an opaque GcsApiError, so the same call is repeated
# against the JSON API, which states the reason verbatim. Both are shown: the first
# is what an operator sees, the second is what a reviewer needs.
set -uo pipefail
source "$(dirname "$0")/env.sh"

OBJ="certificates/day1-seal-check.json"
ENC="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$OBJ")"
API="https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${ENC}"
TOK="$(gcloud auth print-access-token 2>/dev/null)"

rule() { printf '%s\n' "==============================================================="; }
meta() {
  curl -s -H "Authorization: Bearer ${TOK}" "$API" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d:
    print("  object not present"); sys.exit(0)
for k in ("name", "timeCreated", "retentionExpirationTime"):
    print(f"  {k:<24} {d.get(k)}")
'
}

rule; echo " the retention policy on the certificate bucket"; rule
gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" \
  --format="yaml(name,location,retention_policy)"
echo

rule; echo " the sealed object"; rule
if ! curl -s -o /dev/null -f -H "Authorization: Bearer ${TOK}" "$API"; then
  TMP="$(mktemp)"
  printf '{"note":"Day 1 seal check. Written to prove the retention policy refuses deletion and overwrite."}\n' > "$TMP"
  # Checked, because an upload that silently failed used to surface later as
  # "IMMUTABILITY FAILED", naming the wrong cause.
  if ! gcloud storage cp "$TMP" "gs://${BUCKET}/${OBJ}" --project="$PROJECT" >/dev/null 2>&1; then
    echo "could not write the seal-check object; aborting rather than mis-reporting"
    exit 2
  fi
fi
meta
echo

rule; echo " the project owner attempts to delete it"; rule
echo "  acting as: $(gcloud config get-value account 2>/dev/null)"
echo
echo "\$ gcloud storage rm gs://${BUCKET}/${OBJ}"
gcloud storage rm "gs://${BUCKET}/${OBJ}" --project="$PROJECT" 2>&1 | grep -E "ERROR|Removing gs" | head -2
echo
echo "  gcloud reports the refusal without a reason. The same call, verbatim:"
echo "\$ curl -X DELETE https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${ENC}"
DEL="$(curl -s -w '\nHTTP %{http_code}' -X DELETE -H "Authorization: Bearer ${TOK}" "$API")"
echo "$DEL"
echo

rule; echo " and attempts to overwrite it"; rule
echo "\$ curl -X POST .../upload/storage/v1/b/${BUCKET}/o?name=${ENC}"
PUT="$(curl -s -w '\nHTTP %{http_code}' -X POST \
  -H "Authorization: Bearer ${TOK}" -H "Content-Type: application/json" \
  --data '{"note":"tampered"}' \
  "https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${ENC}")"
echo "$PUT" | python3 -c '
import json, sys
raw = sys.stdin.read()
body, _, code = raw.rpartition("\n")
try:
    e = json.loads(body)["error"]
    print(json.dumps({"code": e["code"], "reason": e["errors"][0]["reason"], "message": e["message"]}, indent=2))
except Exception:
    print(body)
print(code)
'
echo

if echo "$DEL" | grep -q "retentionPolicyNotMet" && echo "$PUT" | grep -q "retentionPolicyNotMet"; then
  echo "RESULT: delete REFUSED and overwrite REFUSED by the Cloud Storage retention policy."
else
  echo "RESULT: *** IMMUTABILITY FAILED ***"
  exit 1
fi
echo

rule; echo " the object is unchanged"; rule
meta

rule; echo " and attempts to remove the retention policy itself"; rule
echo "  An unlocked policy can be cleared by the owner and the object deleted after."
echo "  A locked one cannot, which is what closes that path."
echo
# This probe is only safe against a locked policy. Against an unlocked one the
# PATCH succeeds, strips the protection and leaves the bucket open, so the check
# that proves the lock would be the thing that removes it.
LOCKED="$(gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" \
          --format='value(retention_policy.isLocked)')"
if [ "$LOCKED" != "True" ]; then
  echo "  SKIPPED: the retention policy is not locked. Attempting the removal would"
  echo "  succeed and strip it. Run 60_lock_retention.sh first."
  echo
  echo "RESULT: delete and overwrite refused, but the policy is UNLOCKED and removable."
  exit 1
fi
echo "\$ curl -X PATCH https://storage.googleapis.com/storage/v1/b/${BUCKET} -d '{\"retentionPolicy\":null}'"
CLR="$(curl -s -w '\nHTTP %{http_code}' -X PATCH -H "Authorization: Bearer ${TOK}" \
  -H "Content-Type: application/json" --data '{"retentionPolicy":null}' \
  "https://storage.googleapis.com/storage/v1/b/${BUCKET}")"
echo "$CLR" | python3 -c '
import json, sys
raw = sys.stdin.read()
body, _, code = raw.rpartition("\n")
try:
    e = json.loads(body)["error"]
    print(json.dumps({"code": e["code"], "reason": e["errors"][0]["reason"], "message": e["message"]}, indent=2))
except Exception:
    print(body)
print(code)
'
echo
if echo "$CLR" | grep -q "locked Retention Policy which cannot be removed"; then
  echo "RESULT: the retention policy itself is REFUSED removal. The lock holds."
else
  echo "RESULT: *** the retention policy was removable ***"
  exit 1
fi
