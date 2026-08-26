#!/usr/bin/env python3
"""One turn of conversation with the deployed Analyst Copilot, over ADK's own API.

Extracted from `infra/110_run_loop.py` so a second caller can drive the same
surface without importing the loop driver. That module imports the Proposer's
drafting code and the A2A client at module scope, so importing it to reach one
HTTP helper starts a fan-out client and a policy parser as a side effect.

Not A2A. `adk deploy cloud_run --with_ui` serves ADK's API server and its chat
window, and it publishes no agent card, so there is nothing for the registry to
list and nothing for `drive_agent` to speak to. What this reaches is the same
app a person uses, running the same two tools under analyst-sa.

This module only says things. It never writes a review row itself: the
Copilot's own tools do that, under their own identity, and reading the row back
is a separate query against `review.decisions`. Keeping the write on the far
side of the service is the property the entry claims, so it is not a detail this
module is allowed to optimise away.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from typing import Dict, List, Optional

from . import creds

APP = "analyst_copilot"
SERVICE = "caseharden-analyst-copilot"

# `gcloud run services describe` is a shell-out of about a second. The URL of a
# deployed service does not change between calls, and a chat surface asks for it
# on every message.
_URL_CACHE: Dict[str, str] = {}


def service_url(service: str = SERVICE, region: Optional[str] = None) -> str:
    """The deployed service's URL, resolved once per process."""
    region = region or creds.REGION
    key = f"{service}/{region}"
    if key in _URL_CACHE:
        return _URL_CACHE[key]
    out = subprocess.run(
        ["gcloud", "run", "services", "describe", service, "--region", region,
         "--format", "value(status.url)"],
        capture_output=True, text=True, env=creds.gcloud_env())
    url = out.stdout.strip()
    if not url:
        raise RuntimeError(
            f"no such Cloud Run service: {service} in {region}"
            + (f": {out.stderr.strip().splitlines()[-1]}" if out.stderr.strip() else ""))
    _URL_CACHE[key] = url
    return url


def _headers(base: str) -> Dict[str, str]:
    # Imported here rather than at module scope. `agents.common.auth` is the
    # fleet's package and this one is the library the fleet imports; a top-level
    # import would point that dependency both ways. Nothing in the offline path
    # reaches this function, so the offline path never loads it.
    from agents.common import auth

    headers = {"Content-Type": "application/json"}
    token = auth.id_token(auth.origin(base))
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def _post(base: str, path: str, body: dict, headers: Dict[str, str], timeout: float):
    request = urllib.request.Request(
        base + path, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def ensure_session(session: str, user: str = "analyst", base: Optional[str] = None,
                   timeout: float = 60.0) -> None:
    """Create the ADK session if it is not already there.

    ADK answers 400 or 409 for a session that exists, which is the ordinary case
    on every turn after the first. Anything else is a real failure and is raised.
    """
    base = base or service_url()
    try:
        _post(base, f"/apps/{APP}/users/{user}/sessions/{session}", {},
              _headers(base), timeout)
    except urllib.error.HTTPError as exc:
        if exc.code not in (400, 409):
            raise


def texts(events: List[dict]) -> List[str]:
    """Every text part ADK returned, in order."""
    return [part["text"] for event in events
            for part in ((event.get("content") or {}).get("parts") or [])
            if part.get("text")]


def say(text: str, session: str, user: str = "analyst", base: Optional[str] = None,
        timeout: float = 600.0) -> str:
    """Send one message and return what the Copilot said back.

    The reply is the model's words. It is not evidence that anything was stored:
    a Copilot that says it recorded a verdict and a Copilot that recorded one
    look identical from here. The row in `review.decisions` is the record, and
    the caller reads it separately.
    """
    base = base or service_url()
    ensure_session(session, user, base, timeout=min(timeout, 60.0))
    events = _post(base, "/run", {
        "appName": APP, "userId": user, "sessionId": session,
        "newMessage": {"role": "user", "parts": [{"text": text}]},
    }, _headers(base), timeout)
    return "\n".join(texts(events))
