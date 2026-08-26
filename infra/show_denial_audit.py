#!/usr/bin/env python3
"""Print the Cloud Audit entry for the Proposer's refused read.

The BigQuery error message names the table but not the permission. The audit log
names both, plus the principal, plus granted:false. That triple is the artifact a
reviewer checks, and on Day 3 it becomes a link in the chain.

usage: show_denial_audit.py <project> <service_account_email>
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from caseharden import creds

project, sa = sys.argv[1], sys.argv[2]
flt = (f'protoPayload.authenticationInfo.principalEmail="{sa}" '
       f'AND protoPayload.status.code=7 '
       f'AND protoPayload.methodName="jobservice.query"')

# Audit entries land within about a minute. Poll rather than assume.
for attempt in range(12):
    raw = subprocess.run(
        ["gcloud", "logging", "read", flt, "--limit=1", "--freshness=10m",
         f"--project={project}", "--format=json"],
        # Pinned, like every other gcloud call in this repo. Without it this one
        # ran under whatever gcloud configuration happened to be active, which on
        # the machine that builds this is an employer account. `--project` aims
        # the read; it does not decide who makes it.
        capture_output=True, text=True, env=creds.gcloud_env()).stdout
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
