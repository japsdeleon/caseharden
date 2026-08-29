#!/usr/bin/env python3
"""Publish the deployed fleet into Agent Registry, annotated with the chain root.

Each service already serves its own A2A agent card. This script fetches that
card, adds the block Agent Registry has no field for, and registers the result.
Nothing here writes an agent card by hand, so the roster and the agents cannot
disagree about what the agents are.

The annotation is the Day 3 deferred item: the registry entry names the chain
root of the policy version the worker was registered against. That closes the
loop between "these agents exist" and "here is the evidence their authority
rests on", which are otherwise two unrelated facts a reviewer has to join by
hand.

usage: python3 infra/29_register_fleet.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from agents.common import auth, registry
from caseharden import bq, creds
from caseharden.chain import ChainStore

PROJECT = creds.PROJECT
REGION = creds.REGION

# service name -> (role, check family). The four detectors are one program; the
# family is the only thing that differs, and it differs in the deployment.
FLEET = {
    "caseharden-detector-cross-tenant": ("detector", "cross-tenant"),
    "caseharden-detector-scope-escape": ("detector", "scope-escape"),
    "caseharden-detector-injected-turn": ("detector", "injected-turn"),
    "caseharden-detector-privilege-sequencing": ("detector", "privilege-sequencing"),
    "caseharden-support-agent": ("workload", None),
    "caseharden-foreman": ("orchestrator", None),
    "caseharden-proposer": ("proposer", None),
}


def run_url(service: str) -> str:
    out = subprocess.run(
        ["gcloud", "run", "services", "describe", service, "--region", REGION,
         "--format", "value(status.url)"],
        capture_output=True, text=True, env=creds.gcloud_env())
    return out.stdout.strip()


def fetch_card(base_url: str) -> dict:
    url = base_url.rstrip("/") + "/.well-known/agent-card.json"
    token = auth.id_token(auth.origin(base_url))
    request = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + token} if token else {})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def active_version_and_root() -> tuple:
    """The active conduct-policy version and the root its certificate was sealed at.

    Filtered to the enforced line. The roster annotates workers with the policy
    they are governed by, and that is conduct-policy; without the filter, a
    later-registered line's floor version (active, no root) would be annotated
    onto every worker instead.
    """
    try:
        token = bq.access_token(f"notary-sa@{PROJECT}.iam.gserviceaccount.com")
        rows = [r for r in ChainStore(PROJECT, token).versions()
                if r["active"] in ("true", True)
                and (r.get("policy_id") or "conduct-policy") == "conduct-policy"]
        if not rows:
            return None, None
        return rows[-1]["version"], rows[-1].get("root")
    except Exception as exc:
        print(f"  warning: could not read the active version: {exc}", file=sys.stderr)
        return None, None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    version, root = active_version_and_root()
    print(f"active policy {version} root {(root or '')[:12] or '(none)'}")

    token = creds.access_token()
    registered = 0
    for service, (role, family) in sorted(FLEET.items()):
        base = run_url(service)
        if not base:
            print(f"  skip    {service}: not deployed")
            continue
        try:
            card = fetch_card(base)
        except Exception as exc:
            print(f"  FAIL    {service}: card unreachable: {exc}")
            return 1
        annotated = registry.annotate(
            card, role=role, family=family, policy_version=version,
            chain_root=root,
            card_url=base.rstrip("/") + "/.well-known/agent-card.json")
        if args.dry_run:
            print(f"  would   {service} role={role} family={family}")
            continue
        registry.register(PROJECT, REGION, token, service, annotated,
                          display_name=card.get("name", service),
                          description=card.get("description", "")[:2048])
        registered += 1
        print(f"  ok      {service} role={role} family={family or '-'}")

    if not args.dry_run:
        print(f"registered {registered} services into Agent Registry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
