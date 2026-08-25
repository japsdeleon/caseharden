#!/usr/bin/env python3
"""Strip the broad project-wide entries from a dataset's access list.

BigQuery seeds every new dataset with projectReaders/projectWriters, which means
"anyone holding a project-level BigQuery role". A holdout that inherits those is
not sealed. This leaves owners and the explicit grants only.

usage: bq_seal_dataset.py <project> <dataset>
"""
import json
import subprocess
import sys

project, dataset = sys.argv[1], sys.argv[2]
ref = f"{project}:{dataset}"
ds = json.loads(subprocess.run(
    ["bq", f"--project_id={project}", "show", "--format=prettyjson", ref],
    capture_output=True, text=True, check=True).stdout)

before = len(ds.get("access", []))
ds["access"] = [a for a in ds.get("access", [])
                if a.get("specialGroup") not in ("projectReaders", "projectWriters")]

if len(ds["access"]) == before:
    print(f"{dataset}: already sealed")
    sys.exit(0)

with open("/tmp/_seal.json", "w") as fh:
    json.dump(ds, fh)
subprocess.run(["bq", f"--project_id={project}", "update", "--source", "/tmp/_seal.json", ref],
               check=True, capture_output=True)
print(f"{dataset}: dropped {before - len(ds['access'])} project-wide access entries")
