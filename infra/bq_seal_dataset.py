#!/usr/bin/env python3
"""Reduce a dataset's access list to what it is actually supposed to be.

BigQuery seeds a new dataset with `projectReaders`, `projectWriters` and
`projectOwners`, plus an owner entry for whoever created it. Those are inherited,
not granted, and a holdout that keeps them is not sealed. An audit found the
project owner reading 5,421 rows out of a dataset documented as having exactly
one reader, with a capture three lines above the access list calling examiner-sa
its only principal.

Two modes:

  --sole-owner EMAIL   the access list becomes exactly that one entry. BigQuery
                       requires every dataset to keep an OWNER, so the sealed
                       holdout is owned by the one principal meant to read it
                       rather than reduced to a reader alongside inherited owners.
  (default)            strip only the inherited project-wide reader and writer
                       entries, leaving explicit grants and ownership alone.

`bigquery.tables.getData` is not part of `roles/owner`, so removing the owner
entries genuinely removes the read rather than hiding it. `bigquery.datasets.update`
IS part of `roles/owner`, so a project owner can always put an entry back. The
seal is honest about what it is: a list a reviewer can read, enforced by BigQuery,
changeable only by an action that leaves an audit record.

usage: bq_seal_dataset.py <project> <dataset> [--sole-owner EMAIL]
"""
import json
import subprocess
import sys

project, dataset = sys.argv[1], sys.argv[2]
sole_owner = None
if "--sole-owner" in sys.argv:
    sole_owner = sys.argv[sys.argv.index("--sole-owner") + 1]

ref = f"{project}:{dataset}"
ds = json.loads(subprocess.run(
    ["bq", f"--project_id={project}", "show", "--format=prettyjson", ref],
    capture_output=True, text=True, check=True).stdout)

before = ds.get("access", [])
if sole_owner:
    ds["access"] = [{"role": "OWNER", "userByEmail": sole_owner}]
else:
    ds["access"] = [a for a in before
                    if a.get("specialGroup") not in ("projectReaders", "projectWriters")]

if ds["access"] == before:
    print(f"{dataset}: already sealed")
    sys.exit(0)

with open("/tmp/_seal.json", "w") as fh:
    json.dump(ds, fh)
r = subprocess.run(["bq", f"--project_id={project}", "update", "--source", "/tmp/_seal.json", ref],
                   capture_output=True, text=True)
if r.returncode:
    print(f"{dataset}: update refused\n{r.stdout}{r.stderr}")
    sys.exit(1)

print(f"{dataset}: {len(before)} access entries -> {len(ds['access'])}")
for a in ds["access"]:
    print(f"  {a.get('role'):<6} {a.get('userByEmail') or a.get('specialGroup')}")
