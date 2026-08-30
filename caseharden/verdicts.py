#!/usr/bin/env python3
"""The verdict taxonomy: the four things an analyst's disposition can be.

Why this exists. `record_verdict` in `agents/copilot/agent.py` took a
`disposition: str` and wrote it to `review.decisions` verbatim, and its own
docstring offered "confirmed abuse", "false positive" and "needs more evidence"
as examples. So the model picked a phrasing per call. `infra/110_run_loop.py`
then read that row, checked only that Model Armor had screened it, and called
`draft_loop` unconditionally. Every phrasing drafted a policy, including the two
that mean there was nothing here: a verdict of "needs more evidence" produced a
candidate policy version exactly as "confirmed abuse" did.

The disposition is therefore not free text. It is the control value the loop
branches on, and a control value with an open vocabulary is a branch nothing can
take. The rationale beside it stays free text and is stored whatever it says,
because that is the analyst's own words and the record holds what a human typed.
The disposition is not their words; it is what the machine reads.

One member drafts. `confirmed abuse` is the analyst saying the flagged activity
is real misuse, and it is the only answer that justifies a new policy version.
The other three are **terminal**: the loop closes, the verdict stands in
`review.decisions` as the record of the review, and no candidate is drafted.

The names are the ones this repository already uses. `caseharden/workbench.html`
offers an analyst two buttons, `confirmed abuse` and `benign`, and CONTEXT.md
defines a benign turn as legitimate activity a correct policy must allow, so
"false positive" would be a second word for something already named. The two
added are the answers those buttons cannot express: the analyst who cannot tell
from the record, and the analyst for whom this is not the call to make.

What is deliberately not here is a synonym table. `normalise` folds case and
collapses whitespace and does nothing else, so "false positive" is refused
rather than read as `benign`. A caller that decides which member a phrase meant
is deciding the review, and the person who could have said which one is still in
the chat window at the moment the Copilot refuses.

Rows written before this file existed carry free text. `member` answers None for
them, and None is not a member and not an absence: it is a disposition this code
cannot read, which is the answer `unknown` gives about attestation. Callers
freeze the forward action and say what they found. None of them reinterprets.
"""

from __future__ import annotations

import re
from typing import Optional

# The one disposition a policy may be drafted from.
DRAFTS = "confirmed abuse"

# The three that end the loop. Each is an answer, not a failure to answer.
TERMINAL = ("benign", "insufficient evidence", "escalate")

MEMBERS = (DRAFTS,) + TERMINAL

# What each member says, in the analyst's own terms. Carried here rather than
# written out at each call site because both the Copilot's refusal and the
# driver's closing message state it, and two hand-kept copies of a vocabulary go
# out of step the first time a member is added.
MEANING = {
    DRAFTS: "the flagged activity is real misuse and the fleet should deny it",
    "benign": "the check fired on legitimate activity and no rule is needed",
    "insufficient evidence": "the record does not support a call either way",
    "escalate": "this is not the reviewing analyst's call to make",
}

_SPACES = re.compile(r"\s+")


def normalise(disposition: str) -> str:
    """Fold case and collapse whitespace. Nothing else is done to the value.

    Case and spacing are not meaning: an analyst who typed "Confirmed Abuse"
    said the same thing as one who typed "confirmed abuse", and the row should
    carry one spelling so a reader is not comparing phrasings. Every other
    difference is meaning and is left to `member` to refuse.
    """
    return _SPACES.sub(" ", str(disposition or "")).strip().casefold()


def member(disposition: str) -> Optional[str]:
    """The taxonomy member this disposition is, or None if it is not one."""
    folded = normalise(disposition)
    return folded if folded in MEMBERS else None


def offer() -> str:
    """The taxonomy on one line, for a message to a person or to a model."""
    return "; ".join(f"{m!r}: {MEANING[m]}" for m in MEMBERS)
