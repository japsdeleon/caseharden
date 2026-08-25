#!/usr/bin/env python3
"""Send one message to a deployed A2A agent and print what comes back.

The fleet's services are private, so every request carries an identity token for
the service it is addressed to. This is the client the proofs and the demo use;
there is no unauthenticated path to any agent in this project.

usage:
  python3 infra/drive_agent.py --service caseharden-foreman --text "scan the last 72 hours"
  python3 infra/drive_agent.py --url https://... --text "..." --state '{"tenant_id":"t_014"}'
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from agents.common import auth
from caseharden import creds


def service_url(service: str) -> str:
    out = subprocess.run(
        ["gcloud", "run", "services", "describe", service, "--region", creds.REGION,
         "--format", "value(status.url)"],
        capture_output=True, text=True, env=creds.gcloud_env())
    url = out.stdout.strip()
    if not url:
        raise SystemExit(f"no such Cloud Run service: {service}")
    return url


def card(base: str) -> dict:
    token = auth.id_token(auth.origin(base))
    request = urllib.request.Request(
        base.rstrip("/") + "/.well-known/agent-card.json",
        headers={"Authorization": "Bearer " + token} if token else {})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def rpc_url(base: str, agent_card: dict) -> str:
    for interface in agent_card.get("supportedInterfaces", []):
        if interface.get("protocolBinding") in ("JSONRPC", "jsonrpc"):
            return interface["url"]
    return agent_card.get("url") or base


def send(base: str, text: str, context_id: str, timeout: float) -> dict:
    agent_card = card(base)
    target = rpc_url(base, agent_card)
    body = {
        "jsonrpc": "2.0",
        "id": uuid.uuid4().hex,
        "method": "message/send",
        "params": {"message": {
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
            "messageId": uuid.uuid4().hex,
            "contextId": context_id,
        }},
    }
    token = auth.id_token(auth.origin(target))
    request = urllib.request.Request(
        target, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 **({"Authorization": "Bearer " + token} if token else {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def texts(answer: dict):
    """Every text part in an A2A response, whatever shape it came back in."""
    out = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("kind") == "text" and node.get("text"):
                out.append(node["text"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(answer)
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service")
    parser.add_argument("--url")
    parser.add_argument("--text", required=True)
    parser.add_argument("--context", default="")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    base = args.url or (service_url(args.service) if args.service else None)
    if not base:
        raise SystemExit("pass --service or --url")

    answer = send(base, args.text, args.context or uuid.uuid4().hex, args.timeout)
    if args.json:
        print(json.dumps(answer, indent=2))
        return 0
    if "error" in answer:
        print(json.dumps(answer["error"], indent=2))
        return 1
    for part in texts(answer):
        print(part)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
