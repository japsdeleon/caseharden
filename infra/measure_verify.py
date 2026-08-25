#!/usr/bin/env python3
"""Measure the verify SLO, so the README publishes a number instead of a target.

Times the re-derivation itself: two partition-pruned BigQuery scans, one dataset
metadata read, one Examiner re-score over the sealed holdout, and the hash walk.
Token minting is timed separately and reported apart, because it is a property of
running this from a laptop through gcloud impersonation. On Cloud Run the runtime
supplies the identity and that cost is not paid per call.

usage: python3 infra/measure_verify.py --version v4 --runs 20
"""
import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from caseharden import bq, chain  # noqa: E402
from caseharden.notary import verify  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--project", default=os.environ.get("PROJECT", "devpost-hackathon-506416"))
parser.add_argument("--version", default="v4")
parser.add_argument("--runs", type=int, default=20)
args = parser.parse_args()

started = time.monotonic()
notary_token = bq.access_token(f"notary-sa@{args.project}.iam.gserviceaccount.com")
examiner_token = bq.access_token(f"examiner-sa@{args.project}.iam.gserviceaccount.com")
mint = time.monotonic() - started

evidence = chain.BigQueryEvidence(args.project, notary_token, examiner_token)
store = chain.ChainStore(args.project, notary_token)
links = store.read(args.version)
rows = [r for r in store.versions() if r["version"] == args.version]
sealed = chain.sealed_root(rows[0]["certificate_uri"]) if rows else None

samples = []
for i in range(args.runs):
    att = verify(args.version, links, evidence, sealed)
    if not att.attested:
        raise SystemExit(f"run {i}: {args.version} is {att.state}; measure a green version")
    samples.append(att.elapsed_s)

samples.sort()
p = lambda q: samples[min(len(samples) - 1, int(q * len(samples)))]  # noqa: E731
print(f"{args.version}: {len(links)} links, {args.runs} runs")
print(f"  p50 {p(0.50):.2f}s   p95 {p(0.95):.2f}s   max {samples[-1]:.2f}s   "
      f"mean {statistics.mean(samples):.2f}s")
print(f"  token minting, paid once per process and not per verify: {mint:.1f}s "
      f"for two impersonated tokens")
