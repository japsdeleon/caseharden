#!/usr/bin/env python3
"""The Policy Server: the enforcement point that makes the record load-bearing.

Serving a policy is the easy half. The half that matters is that every response
carries the version's live attestation state, and that the promotion path is
closed whenever that state is not green. Without this endpoint the chain is a
report; with it, changing the evidence changes what the fleet is allowed to do
next.

Attestation gates authority, not availability: `policy` is served whatever the
state says, because an audit layer that switches off guardrails is a worse
failure than the one it detects. What a break withdraws is `attested` and
`promotions`.

usage: python -m caseharden.policy_server --port 8080
  GET /policy/v4                    the version, its policy document, and its live state
  GET /policy/active                the conduct-policy line's active version
  GET /policy/<line>/active         a named policy line's active version
  GET /policy/<line>/<version>      a version addressed through its line
  GET /healthz
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple

from . import bq, chain
from .chain import ChainStore
from .notary import UNKNOWN, verify

CACHE_SECONDS = 60


def identities(project: str):
    """The two principals verification needs: the chain reader and the examiner.

    On a workstation the operator impersonates each in turn. In a container
    there is one identity and it is examiner-sa, because re-scoring the exam at
    serve time requires the only principal allowed to read it. Handing the
    Policy Server the power to impersonate examiner-sa instead would put a
    second principal within reach of the exam without adding a row to
    holdout_sealed's access list, which is exactly the hole that list exists to
    make visible.
    """
    from . import creds

    if creds.on_cloud_run():
        attached = creds.attached_service_account()
        return attached, attached
    return (f"notary-sa@{project}.iam.gserviceaccount.com",
            f"examiner-sa@{project}.iam.gserviceaccount.com")


class Attestations:
    """Verify results, cached for 60s.

    Verification re-scans BigQuery, so serving it per request would put the
    warehouse in the hot path of every tool call. 60s is the window in which a
    tamper is still enforced-but-attested, and it is stated rather than hidden:
    every response carries `checked_s_ago`.

    Cache entries are ordered by when their verification STARTED, not by when it
    finished. Two refreshes can overlap, and the slower one finishes last: an
    adversarial pass raced a slow ATTESTED verification against a later
    QUARANTINED one and the stale green won, reopening promotions for a further
    60 seconds. An older answer never replaces a newer one.
    """

    def __init__(self, project: str, ttl: int = CACHE_SECONDS):
        self.project = project
        self.ttl = ttl
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[float, dict]] = {}
        # The last state that was actually established. `unknown` is defined as
        # "last known state retained", which needs somewhere to retain it.
        self._last_known: Dict[str, dict] = {}

    def _fresh(self, version: str) -> dict:
        notary, examiner = identities(self.project)
        try:
            token = bq.access_token(notary)
            evidence = chain.BigQueryEvidence(self.project, token,
                                             bq.access_token(examiner))
            store = ChainStore(self.project, token)
            links = store.read(version)
            rows = [r for r in store.versions() if r["version"] == version]
            sealed = (chain.sealed_root(rows[0]["certificate_uri"], notary)
                      if rows and rows[0].get("certificate_uri") else None)
            attestation = verify(version, links, evidence, sealed)
            att = attestation.as_dict()
            # The policy served is the policy the chain attests to, read out of
            # the EXAM link, not the copy in policy.versions. Serving the
            # registry copy made the attested artifact and the enforced artifact
            # two different objects, with nothing comparing them.
            att["policy"] = _attested_policy(links)
            att["policy_line"] = ((rows[0].get("policy_id") or "conduct-policy")
                                  if rows else None)
            registered = json.loads(rows[0]["policy"]) if rows else None
            att["registry_agrees"] = registered == att["policy"]
            if not att["registry_agrees"]:
                att["attested"] = False
                att["promotions"] = "FROZEN"
                att["registry_mismatch"] = (
                    "policy.versions serves a different document from the one the "
                    "chain attests to")
            with self._lock:
                self._last_known[version] = {"state": att["state"],
                                             "root": att.get("root")}
        except Exception as exc:  # noqa: BLE001 - any failure is the unknown state
            # The one branch that must never fall through to attested. A version
            # whose state cannot be established is not a version in good standing.
            att = {"version": version, "attested": False, "state": UNKNOWN.upper(),
                   "promotions": "FROZEN", "error": str(exc)}
            with self._lock:
                last = self._last_known.get(version)
            att["last_known"] = last
            # The alert. A local service has stderr and nothing else; on Cloud Run
            # this line is a log entry an alerting policy can match on.
            print(f"ALERT caseharden attestation UNKNOWN version={version} "
                  f"last_known={(last or {}).get('state')} reason={exc}",
                  file=sys.stderr, flush=True)
        return att

    def get(self, version: str) -> dict:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(version)
        if hit and now - hit[0] < self.ttl:
            return dict(hit[1], checked_s_ago=round(now - hit[0], 1), cached=True)
        started = time.monotonic()
        att = self._fresh(version)
        with self._lock:
            current = self._cache.get(version)
            if current is None or started > current[0]:
                self._cache[version] = (started, att)
            else:
                # A newer verification already landed while this one was running.
                # Serve that answer rather than this stale one.
                att = current[1]
        return dict(att, checked_s_ago=0.0, cached=False)

    def active_version(self, policy_id: str = "conduct-policy") -> Optional[str]:
        token = bq.access_token(identities(self.project)[0])
        rows = [r for r in ChainStore(self.project, token).versions()
                if r["active"] in ("true", True)
                and (r.get("policy_id") or "conduct-policy") == policy_id]
        return rows[-1]["version"] if rows else None


def parse_policy_path(path: str) -> Optional[Tuple[str, str]]:
    """(policy line, version) for a /policy path, or None for any other.

    Two shapes: `/policy/<version>` keeps its pre-lines meaning and belongs to
    `conduct-policy`; `/policy/<line>/<version>` names the line. `active` is a
    version placeholder in both.
    """
    if not path.startswith("/policy/"):
        return None
    parts = path[len("/policy/"):].split("/")
    if len(parts) == 1 and parts[0]:
        return "conduct-policy", parts[0]
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    return None


def _attested_policy(links) -> Optional[dict]:
    """The candidate policy the chain's effective exam measured."""
    exam = None
    for link in links:
        if link.kind == "EXAM":
            exam = link.payload
        if link.kind == "EVIDENCE-CHANGED" and "exam" in link.payload:
            exam = link.payload["exam"]
    return exam.get("candidate") if exam else None


def handler_for(attestations: Attestations):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, body: dict) -> None:
            raw = json.dumps(body, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
            path = self.path.split("?")[0].rstrip("/")
            if path == "/healthz":
                return self._send(200, {"ok": True})
            route = parse_policy_path(path)
            if route is None:
                return self._send(404, {"error": "no such path"})
            line, version = route
            if not line.replace("-", "").replace("_", "").isalnum():
                return self._send(400, {"error": "not a usable policy line name"})
            if version == "active":
                try:
                    version = attestations.active_version(line)
                except Exception as exc:  # noqa: BLE001
                    # An enforcement callback that does not know the version
                    # number calls exactly this path. It gets a state, not a
                    # dropped connection.
                    print(f"ALERT caseharden cannot resolve the active version: {exc}",
                          file=sys.stderr, flush=True)
                    return self._send(200, {"version": None, "attested": False,
                                            "state": UNKNOWN.upper(),
                                            "promotions": "FROZEN", "error": str(exc)})
                if version is None:
                    return self._send(404, {"error": "no active version"})
            if not version.replace("-", "").replace("_", "").isalnum():
                return self._send(400, {"error": "not a usable version name"})
            att = attestations.get(version)
            # A version addressed through a line it does not belong to is not
            # served through it: /policy/payments-policy/v5 must not answer
            # with conduct-policy's document. A version with no registry row
            # has no line to check and is served as the unknown it is.
            if att.get("policy_line") not in (None, line):
                return self._send(404, {
                    "error": f"{version} is not a version of policy line {line}"})
            return self._send(200, att)

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Serve conduct policy with its attestation state.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    parser.add_argument("--project", default=os.environ.get("CASEHARDEN_PROJECT",
                                                            "devpost-hackathon-506416"))
    parser.add_argument("--ttl", type=int, default=CACHE_SECONDS)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer(("", args.port), handler_for(Attestations(args.project, args.ttl)))
    print(f"policy server on :{args.port}, attestation cached {args.ttl}s")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
