#!/usr/bin/env python3
"""The Foreman: fans an investigation out to whatever the registry says exists.

No check family is named anywhere in this file, and the fleet proof greps for all
four to keep it that way. The Foreman calls Agent Registry, takes back agent
cards, and binds each one as a RemoteA2aAgent at startup. Deploying a fifth
detector adds a fifth span to the fan-out with no edit here; deleting one removes
it.

That is the whole point of the registry in this entry. A roster a reviewer can
list from outside the process is a different object from a list of URLs compiled
into an orchestrator, because the first one can be checked and the second can
only be read. Each card also carries the chain root of the policy version its
detector was built against, so the roster states what each worker's authority
rests on rather than just where it lives.
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.tools import load_memory

from agents.common import auth, memory, registry
from caseharden import creds

# ADK reads Application Default Credentials. On this build machine those were
# an unrelated employer identity, so nothing starts until ADC is checked.
creds.guard_ambient()

PROJECT = creds.PROJECT
REGION = creds.REGION
MODEL = os.environ.get("CASEHARDEN_MODEL", "gemini-3.5-flash")
CARD_PATH = "/.well-known/agent-card.json"


def discover(role: str = "detector") -> List[dict]:
    """Every registered agent with this role, as agent cards.

    Failure here is loud on purpose. A Foreman that starts with an empty roster
    because the registry call failed looks exactly like a Foreman with nothing to
    do, and would report a clean fleet by saying nothing at all.
    """
    cards = registry.list_agents(PROJECT, REGION, creds.access_token())
    return [c for c in cards if registry.annotation(c).get("role") == role]


def bind(cards: List[dict]) -> List[RemoteA2aAgent]:
    bound = []
    for card in cards:
        card_url = registry.annotation(card).get("card_url")
        if not card_url:
            # Derive it from the RPC url rather than skipping the agent: an
            # older card that predates the annotation is still a real worker.
            base = (card.get("url") or "").split("/a2a/")[0]
            card_url = base.rstrip("/") + CARD_PATH if base else None
        if not card_url:
            continue
        timeout = float(os.environ.get("CASEHARDEN_A2A_TIMEOUT", "120"))
        bound.append(RemoteA2aAgent(
            name=str(card.get("name", "worker")).replace("-", "_"),
            description=card.get("description", ""),
            agent_card=card_url,
            timeout=timeout,
            # The detectors are private Cloud Run services. Every hop is signed
            # for the service it is addressed to; see agents/common/auth.py.
            httpx_client=auth.signing_client(timeout),
        ))
    return bound


SUMMARY_INSTRUCTION = """You are the Foreman of a conduct-detection fleet.

Every detector above has already answered. Their replies are in the conversation.

Produce one finding report:
- One line per detector: its family, its count, and its BigQuery job id verbatim.
- Then the single most serious pattern across all of them, naming the session ids
  and event ids the detectors gave you.
- Then, in one line, what a reviewer would have to look at to disagree.

Never invent a count, an id or a job id. If a detector reported that its scan did
not run, say so on its line instead of reporting zero. You do not decide policy
and you do not say whether anything should be blocked; a separate examiner does
that and it is not you.

Use the load_memory tool once, first, to check whether this pattern has been
reviewed before, and say what it found or that it found nothing."""


ENGINE = os.environ.get("CASEHARDEN_MEMORY_ENGINE", "")


def _report_text(callback_context) -> str:
    """The finding report this run produced, from the session's own events."""
    session = getattr(callback_context, "session", None)
    parts = []
    for event in reversed(getattr(session, "events", []) or []):
        content = getattr(event, "content", None)
        for part in (getattr(content, "parts", None) or []):
            text = getattr(part, "text", None)
            if text and text.strip():
                parts.append(text.strip())
        if parts:
            break
    return "\n".join(parts)


async def remember(callback_context) -> None:
    """File this investigation as precedent for the next one.

    What `load_memory` surfaces later is the fleet's own review history, written
    here after each report. Nothing is seeded by hand, so an empty answer on the
    first run is the honest one.

    Written directly rather than through `add_session_to_memory`. That call is a
    coroutine, so an early version never awaited it and left a RuntimeWarning in
    the logs; awaiting it then raised nothing and still stored nothing, which is
    worse, because a silent no-op and an empty history look identical. See
    agents/common/memory.py.
    """
    report = _report_text(callback_context)
    if not report:
        return
    try:
        memory.write(ENGINE, PROJECT, REGION, creds.access_token,
                     f"Conduct finding reviewed by the fleet:\n{report}")
    except Exception as exc:
        print(f"ALERT caseharden could not file this session as precedent: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True)


def build() -> SequentialAgent:
    workers = bind(discover())
    summarizer = LlmAgent(
        model=MODEL,
        name="finding_writer",
        description="Collates the detectors' answers into one finding report.",
        instruction=SUMMARY_INSTRUCTION,
        tools=[load_memory],
        after_agent_callback=remember,
    )
    if not workers:
        # Say it out loud rather than silently degrading to a one-agent fleet.
        summarizer.instruction = (
            "Report exactly this and nothing else: the Agent Registry returned no "
            "detectors with role=detector, so no scan was performed. Do not "
            "speculate about what the fleet would have found.")
        return SequentialAgent(name="foreman", sub_agents=[summarizer])
    return SequentialAgent(
        name="foreman",
        description="Fans an investigation out to every registered conduct detector.",
        sub_agents=[
            ParallelAgent(name="fan_out",
                          description="Every registered detector, in parallel.",
                          sub_agents=workers),
            summarizer,
        ],
    )


root_agent = build()
