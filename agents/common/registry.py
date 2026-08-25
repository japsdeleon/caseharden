#!/usr/bin/env python3
"""Agent Registry: how a worker announces itself, and how the Foreman finds it.

Two calls, and the second is the one the entry is about. `register` publishes an
A2A agent card for a deployed service. `list_agents` reads the registry back and
returns cards. The Foreman binds whatever `list_agents` returns; it holds no list
of detectors, so adding a fifth is a deploy, not an edit.

Each detector's card carries the chain root of the policy version it was built
to enforce, under `caseharden`. A registry entry that names a root a reviewer can
re-derive is the difference between a directory of endpoints and a roster of
agents whose authority can be checked from outside the agent.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

API = ("https://agentregistry.googleapis.com/v1alpha/projects/{project}"
       "/locations/{region}/services")
AGENTS_API = ("https://agentregistry.googleapis.com/v1alpha/projects/{project}"
              "/locations/{region}/agents")


class RegistryError(RuntimeError):
    pass


def _call(url: str, token: str, method: str = "GET",
          body: Optional[dict] = None, timeout: float = 30.0) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RegistryError(exc.read().decode()[:600]) from None


EXTENSION_URI = "https://caseharden.dev/ext/attestation/v1"


def annotate(card: dict, role: str, family: Optional[str] = None,
             policy_version: Optional[str] = None,
             chain_root: Optional[str] = None,
             card_url: Optional[str] = None) -> dict:
    """Add this project's block to a card the agent itself published.

    The card is not written here. Each service serves its own at
    /.well-known/agent-card.json and that document is what gets registered, so
    the roster cannot drift from what the agents actually are. What is added is
    the part A2A has no field for: the role, the check family, and the chain
    root of the policy version this worker was registered against.

    It goes in `capabilities.extensions`, which is where the A2A spec puts
    exactly this. A top-level key is rejected: Agent Registry validates the card
    against the v1.0 proto and answers `unknown field "caseharden"`.
    """
    out = json.loads(json.dumps(card))  # deep copy; the caller keeps its card
    params = {"role": role, "family": family or "",
              "policy_version": policy_version or "",
              "chain_root": chain_root or "", "card_url": card_url or ""}
    extensions = out.setdefault("capabilities", {}).setdefault("extensions", [])
    extensions = [e for e in extensions if e.get("uri") != EXTENSION_URI]
    extensions.append({
        "uri": EXTENSION_URI,
        "description": ("Caseharden roster annotation: the worker's role and the "
                        "chain root of the policy version it was registered "
                        "against."),
        "required": False,
        "params": params,
    })
    out["capabilities"]["extensions"] = extensions
    return out


def annotation(card: dict) -> dict:
    """This project's block, read back off a registered card. Empty when absent."""
    for extension in ((card.get("capabilities") or {}).get("extensions") or []):
        if extension.get("uri") == EXTENSION_URI:
            return dict(extension.get("params") or {})
    return {}


def register(project: str, region: str, token: str, service_id: str,
             card: dict, display_name: str = "", description: str = "") -> dict:
    """Create the registry service, or update the card if it is already there."""
    base = API.format(project=project, region=region)
    body = {
        "displayName": display_name or service_id,
        "description": description or card.get("description", "")[:2048],
        # content is a protobuf Struct, so the card goes across as an object.
        # Sending it as a JSON string is rejected with "Invalid value at
        # service.agent_spec.content".
        "agentSpec": {"type": "a2a-agent-card", "content": card},
    }
    try:
        return _call(f"{base}?serviceId={service_id}", token, "POST", body)
    except RegistryError as exc:
        if "ALREADY_EXISTS" not in str(exc):
            raise
        return _call(f"{base}/{service_id}?updateMask=agentSpec,displayName,description",
                     token, "PATCH", body)


def list_agents(project: str, region: str, token: str) -> List[dict]:
    """Every agent the registry knows in this location, as parsed cards.

    This is the discovery call. The Foreman calls it and binds the result; it is
    the reason no detector name appears anywhere in the Foreman's source.
    """
    out: List[dict] = []
    url = AGENTS_API.format(project=project, region=region)
    page: Optional[str] = None
    while True:
        answer = _call(url + (f"?pageToken={page}" if page else ""), token)
        for entry in (answer.get("agents") or answer.get("items") or []):
            card = _parse_card(entry)
            if card:
                out.append(card)
        page = answer.get("nextPageToken")
        if not page:
            break
    return out


def _parse_card(entry: dict) -> Optional[dict]:
    """The agent card out of a registry entry, whichever shape it arrives in.

    A Service carries `agentSpec.content`; the derived Agent resource carries
    `card.content`. Reading only the first returned an empty roster, and an
    empty roster is indistinguishable from a fleet with nothing to report.
    """
    content = None
    for key in ("card", "agentSpec"):
        holder = entry.get(key) or {}
        if isinstance(holder, dict) and holder.get("content"):
            content = holder["content"]
            break
    if not content:
        return None
    try:
        card = json.loads(content) if isinstance(content, str) else dict(content)
    except (TypeError, ValueError):
        return None
    card["_resource"] = entry.get("name") or entry.get("agentId", "")
    return card


def delete(project: str, region: str, token: str, service_id: str) -> None:
    base = API.format(project=project, region=region)
    _call(f"{base}/{service_id}", token, "DELETE")
