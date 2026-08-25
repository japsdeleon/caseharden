#!/usr/bin/env python3
"""Service-to-service auth for the A2A fan-out.

The fleet's Cloud Run services are deployed private. That is not decoration: a
public endpoint in front of a model is an unmetered way for anyone to spend the
project's credit, and this project has a fixed one. So the Foreman signs each
A2A request with a Google-issued identity token for the exact service it is
calling, and Cloud Run's own IAM check refuses anything else.

Tokens are minted per audience and cached until shortly before they expire. The
audience is the target service's origin, which is what Cloud Run validates
against; sending a token minted for a different service fails closed.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Dict, Optional

IDENTITY = ("http://metadata.google.internal/computeMetadata/v1/instance/"
            "service-accounts/default/identity?audience=")
SKEW_SECONDS = 120

_cache: Dict[str, tuple] = {}


def on_cloud_run() -> bool:
    return bool(os.environ.get("K_SERVICE"))


def _expiry(token: str) -> float:
    """The `exp` claim, without verifying the signature.

    This is not a security check. It decides when to ask for a new token; the
    only party that has to trust this token is Cloud Run, which does verify it.
    """
    import base64

    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return time.time() + 300


def id_token(audience: str) -> Optional[str]:
    """An identity token for one audience, or None when nothing can mint one."""
    hit = _cache.get(audience)
    if hit and hit[1] - SKEW_SECONDS > time.time():
        return hit[0]

    token = _from_metadata(audience) if on_cloud_run() else _from_gcloud(audience)
    if token:
        _cache[audience] = (token, _expiry(token))
    return token


def _from_metadata(audience: str) -> Optional[str]:
    url = IDENTITY + urllib.parse.quote(audience, safe="")
    try:
        request = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read().decode().strip()
    except Exception:
        return None


# On a workstation the operator is a user account, and a user account cannot mint
# an identity token for a custom audience at all: gcloud answers "Invalid account
# type for --audiences. Requires valid service account." So the local path
# impersonates one. This is a workstation convenience, not a production path; in
# a container the metadata server does it and no impersonation is involved.
INVOKER_SA = os.environ.get("CASEHARDEN_INVOKER_SA", "")


def _from_gcloud(audience: str) -> Optional[str]:
    """On a workstation, so the fan-out can be driven locally against real services."""
    import subprocess

    from caseharden import creds

    invoker = INVOKER_SA or f"foreman-sa@{creds.PROJECT}.iam.gserviceaccount.com"
    out = subprocess.run(
        ["gcloud", "auth", "print-identity-token",
         f"--impersonate-service-account={invoker}",
         f"--audiences={audience}", "--include-email"],
        capture_output=True, text=True, env=creds.gcloud_env())
    return out.stdout.strip() or None


def origin(url: str) -> str:
    """The audience Cloud Run validates against: scheme and host, no default port.

    ADK renders an agent card URL as `https://host:443`, and an identity token
    minted for that string does not match the audience Cloud Run expects. The
    request then fails closed with a 401 that looks like a permissions problem
    and is actually a stray port.
    """
    parts = urllib.parse.urlsplit(url)
    netloc = parts.netloc
    for scheme, port in (("https", ":443"), ("http", ":80")):
        if parts.scheme == scheme and netloc.endswith(port):
            netloc = netloc[: -len(port)]
    return f"{parts.scheme}://{netloc}"


def signing_client(timeout: float = 120.0):
    """An httpx.AsyncClient that signs every request for its destination.

    It also carries the W3C traceparent, so the detector's spans land under the
    fan-out that asked for them. Without that header each hop begins its own
    trace and one investigation is four unrelated pictures in Cloud Trace.
    """
    import httpx

    from agents.common import tracing

    async def sign(request):
        token = id_token(origin(str(request.url)))
        if token:
            request.headers["Authorization"] = "Bearer " + token
        for key, value in tracing.inject({}).items():
            request.headers[key] = value

    return httpx.AsyncClient(timeout=timeout, event_hooks={"request": [sign]})
