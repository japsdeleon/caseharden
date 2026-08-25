#!/usr/bin/env python3
"""Print the Cloud Audit entry for the Proposer's refused read.

The BigQuery error message names the table but not the permission. The audit log
names both, plus the principal, plus granted:false. That triple is the artifact a
reviewer checks, and on Day 3 it becomes a link in the chain.

usage: show_denial_audit.py <project> <service_account_email>
"""
import json
import subprocess
import sys
import time

project, sa = sys.argv[1], sys.argv[2]
flt = (f'protoPayload.authenticationInfo.principalEmail="{sa}" '
       f'AND protoPayload.status.code=7 '
       f'AND protoPayload.methodName="jobservice.query"')

# Audit entries land within about a minute. Poll rather than assume.
for attempt in range(12):
    raw = subprocess.run(
        ["gcloud", "logging", "read", flt, "--limit=1", "--freshness=10m",
         f"--project={project}", "--format=json"],
        capture_output=True, text=True).stdout
    entries = json.loads(raw or "[]")
    if entries:
        break
    time.sleep(5)
else:
    print("no audit entry yet; re-run in a minute")
    sys.exit(1)

p = entries[0]["protoPayload"]
denied = [a for a in p.get("authorizationInfo", []) if not a.get("granted")]

print(f"  logName        {entries[0]['logName'].split('%2F')[-1]}")
print(f"  timestamp      {entries[0]['timestamp']}")
print(f"  principalEmail {p['authenticationInfo']['principalEmail']}")
print(f"  methodName     {p['methodName']}")
print(f"  status.code    {p['status']['code']}  (PERMISSION_DENIED)")
for a in denied:
    print(f"  DENIED         {a['permission']}  ({a.get('permissionType')})")
    print(f"                 on {a['resource']}")
if not denied:
    print("  *** no denied permission recorded — the seal did not engage ***")
    sys.exit(1)
