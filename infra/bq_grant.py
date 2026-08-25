#!/usr/bin/env python3
"""Grant a dataset-scoped BigQuery role by patching the dataset access list.

bq add-iam-policy-binding needs an allowlist on some projects; the classic access
list does not, and it is what the BigQuery console shows a reviewer.

usage: bq_grant.py <project> <dataset> <role> <member_email> [...]
"""
import json
import subprocess
import sys

project, dataset, role = sys.argv[1], sys.argv[2], sys.argv[3]
members = sys.argv[4:]

ref = f"{project}:{dataset}"
ds = json.loads(subprocess.run(
    ["bq", f"--project_id={project}", "show", "--format=prettyjson", ref],
    capture_output=True, text=True, check=True).stdout)

access = ds.setdefault("access", [])
have = {(a.get("role"), a.get("userByEmail")) for a in access}
added = [m for m in members if (role, m) not in have]
access.extend({"role": role, "userByEmail": m} for m in added)

if not added:
    print(f"{dataset}: already granted {role} to {', '.join(members)}")
    sys.exit(0)

with open("/tmp/_ds.json", "w") as fh:
    json.dump(ds, fh)
subprocess.run(["bq", f"--project_id={project}", "update", "--source", "/tmp/_ds.json", ref],
               check=True, capture_output=True)
print(f"{dataset}: granted {role} to {', '.join(added)}")
