#!/usr/bin/env python3
"""Writing a finding into Vertex AI Memory Bank, explicitly.

ADK's `add_session_to_memory` hands the session to Memory Bank's generation
path, which extracts memories with a model. Against this engine it accepted
every call, raised nothing, and left the bank empty after six investigations.
An audit caught that: the read path was demonstrated and the write path was not,
and the only visible difference between "wrote nothing" and "had nothing to
write" was that the bank stayed empty.

So the Foreman writes the finding itself. `memories.create` is a direct write
with no extraction step, and what gets stored is the report the fleet actually
produced rather than a model's summary of a conversation about it. Precedent
that was inferred is worth less than precedent that was recorded.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Callable, List, Optional

API = ("https://{region}-aiplatform.googleapis.com/v1beta1/projects/{project}"
       "/locations/{region}/reasoningEngines/{engine}/memories")

# A memory is a fact, not a transcript. Long enough to carry the finding, short
# enough that retrieval returns something a reviewer reads.
MAX_FACT = 4000


def write(engine: str, project: str, region: str, token_fn: Callable[[], str],
          fact: str, scope: Optional[dict] = None, timeout: float = 60.0) -> str:
    """Store one fact. Returns the operation name."""
    if not engine:
        raise ValueError("no memory engine configured")
    body = json.dumps({"fact": fact[:MAX_FACT],
                       "scope": scope or {"agent": "foreman"}}).encode()
    request = urllib.request.Request(
        API.format(region=region, project=project, engine=engine), data=body,
        headers={"Authorization": "Bearer " + token_fn(),
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response).get("name", "")


def read(engine: str, project: str, region: str, token_fn: Callable[[], str],
         timeout: float = 60.0) -> List[dict]:
    """Every stored memory. Used by the fleet proof to show the write landed.

    Raises on a refusal rather than answering with an empty list. Swallowing the
    error made a bank that could not be read indistinguishable from a bank with
    nothing in it, which is the failure this module exists to close on the write
    side. It cost a proof run: an engine id read back through
    `gcloud --format=value(...)` arrived as "['4537...']" rather than the id,
    every request 404'd, and the proof reported an empty Memory Bank for a write
    that had landed four seconds earlier.
    """
    if not engine:
        raise ValueError("no memory engine configured")
    request = urllib.request.Request(
        API.format(region=region, project=project, engine=engine),
        headers={"Authorization": "Bearer " + token_fn()})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response).get("memories", [])
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"Memory Bank refused a read of engine {engine!r}: HTTP {exc.code} "
            f"{exc.read().decode()[:300]}") from None
