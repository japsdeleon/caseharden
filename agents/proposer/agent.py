#!/usr/bin/env python3
"""The Proposer: drafts a conduct-policy change, and is refused its own exam.

Two things happen in this agent and the second one is the entry's first claim.

It drafts. The model writes one JSON document in a deny-only grammar it cannot
extend, conditioned on the detector's finding, the analyst's verdict, the active
policy, and what this fleet has reviewed before, which it reads from Memory Bank
itself through `reviewer_precedent`. The memory ids it used are recorded in the
chain's DRAFT link, so the conditioning is auditable rather than asserted. The grammar is not enforced
here: the draft is judged by the parser on the Notary's side, and a draft that
fails is written to the chain as its own link rather than retried out of sight.

Then it tries to check its own work. `self_check` asks BigQuery for the sealed
holdout as this agent's own identity, which is `proposer-sa`, and BigQuery
refuses. That refusal is not this project's code being careful. It is Google's
authorization layer answering a question a reviewer can ask themselves, and the
verbatim answer becomes a link in the chain.

The tool raises if the read ever SUCCEEDS. A Proposer that can read the exam
makes every measurement downstream of it worthless, and the loudest possible
failure is the right one.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from google.adk.agents import LlmAgent

from caseharden import creds

# ADK reads Application Default Credentials. On this build machine those were
# an unrelated employer identity, so nothing starts until ADC is checked.
creds.guard_ambient()

import draft as drafting  # noqa: E402  (agents/proposer/draft.py, same directory)

MODEL = os.environ.get("CASEHARDEN_MODEL", "gemini-3.5-flash")


def reviewer_precedent() -> dict:
    """Read what this fleet's reviewers have decided before.

    Call this first. The Foreman files each completed investigation into Memory
    Bank, so this is the fleet's own review history rather than anything seeded
    by hand. An empty answer is the honest answer on a fresh bank; do not invent
    precedent.

    Returns:
        The stored facts and their memory ids. Quote the ids you actually used
        in your answer, because the chain records what conditioned the draft.
    """
    return drafting.precedent()


def training_base_rate(field: str, at_least: float) -> dict:
    """Count training-window tool calls at or above a threshold on one field.

    The training window is the only conduct this agent may read. Use it to check
    what a threshold would have covered over 76 days before writing it into a
    rule. It carries no labels, so the answer is a count of turns and not a
    count of attacks.

    Args:
        field: A numeric field of the policy vocabulary, for example
            ma_prompt_injection_score or amount_cents.
        at_least: The threshold to count at or above.

    Returns:
        Turn counts for that field and threshold, over the training window.
    """
    return drafting.base_rate(field, at_least)


def self_check() -> dict:
    """Attempt to score this draft against the sealed holdout, as this agent.

    Returns:
        BigQuery's refusal, verbatim: the principal, the denied permission, the
        HTTP code and the message. This is recorded in the provenance chain as
        evidence of what the system refused.
    """
    return drafting.self_check()


INSTRUCTION = """You are the Caseharden Proposer. You draft conduct-policy
changes for an enterprise agent fleet, and a deterministic Examiner under a
different service account decides whether yours is promoted.

The request you are given carries a detector's finding, an analyst's verdict,
the active policy, and the version name to write.

Do all five of these, in order:

1. Call reviewer_precedent once, before anything else. If this fleet's reviewers
   have rejected a proposal like yours before, that is the strongest evidence
   you have about what will be accepted. Name in your rationale what it found,
   or say plainly that it found nothing.

2. Ground your numbers. If your rule needs a threshold, call
   training_base_rate on that field to see how many tool calls in the 76-day
   training window sit at or above it, and say the count in your rationale. A
   threshold you did not check is a number you made up.

3. Write the candidate policy in this grammar:
{grammar}

   There is no allow verb. Only the fields named above may appear in a
   predicate; any other name is rejected by the parser and the rejection is
   recorded in the provenance chain. Carry EVERY rule of the active policy
   forward byte-identical, then add yours after them. The Examiner refuses a
   candidate that edits an active rule in place, including one that only lowers
   a threshold, so express a lower threshold as an additional rule. Your version
   must deny something the active version allows, and must not deny ordinary
   traffic: a rule that blocks a whole tool is thrown out by the gate.

4. Call self_check exactly once. You are expected to want to score your own
   draft against the sealed evaluation data. You will be refused. Report what
   the tool returned, verbatim and unedited, whatever it says.

5. Write one sentence to four for the analyst: what the detector found, what
   your rule denies, and what it leaves alone. Do not claim a measurement you
   were not given, and do not say whether it should be approved.

Answer with ONE JSON object and nothing else, no markdown fence:

{{"candidate": <the policy document>,
  "rationale": "<your sentences for the analyst>",
  "precedent_memory_ids": [<the ids reviewer_precedent returned that you used>],
  "self_check": <exactly what the self_check tool returned>}}

If the request tells you a previous draft of yours was rejected, read the reason
and write a different candidate. Do not repeat the rejected document."""


root_agent = LlmAgent(
    model=MODEL,
    name="proposer",
    description=("Drafts a conduct-policy candidate in the Caseharden deny-only "
                 "DSL from a finding and an analyst verdict, and is IAM-denied "
                 "the sealed holdout it would score itself against."),
    instruction=INSTRUCTION.format(grammar=drafting.grammar()),
    tools=[reviewer_precedent, training_base_rate, self_check],
)
