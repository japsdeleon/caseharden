#!/usr/bin/env python3
"""Print a BigQuery REST response the way a reviewer needs to read it."""
import json
import sys

d = json.load(sys.stdin)
if "error" in d:
    e = d["error"]
    print("HTTP {}  {}".format(e.get("code"), e.get("status")))
    print(json.dumps(d, indent=2))
    sys.exit(0)
print("HTTP 200   rows:", d["rows"][0]["f"][0]["v"])
