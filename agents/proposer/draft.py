#!/usr/bin/env python3
"""What the Proposer can do besides talk: read the grammar, the training window, and the exam.

Three functions, and the agent in agent.py is the only caller. There is no
second drafting path here: a module that could also draft, without the tools and
the identity the deployed agent has, would be a second thing to keep in step and
a way to produce a candidate no service account ever stood behind.

`grammar` writes the DSL out of dsl.py's own vocabulary rather than restating
it, because a hand-copied vocabulary goes stale the first time a predicate is
added and a stale prompt produces drafts that fail validation for a reason that
is this file's fault rather than the model's.

`base_rate` is the only conduct the Proposer may read: counts over the training
window, which carries no labels.

`self_check` is the refusal. It asks BigQuery for the sealed holdout as this
process's own identity and returns what BigQuery answers, and it raises if the
read ever succeeds.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from caseharden import creds
from caseharden.dsl import ARRAY_FIELDS, NUMERIC_FIELDS, PREDICATE_OPS, STRING_FIELDS


def grammar() -> str:
    """The DSL, written out of dsl.py's own vocabulary."""
    return json.dumps({
        "predicate_ops": list(PREDICATE_OPS),
        "string_fields": list(STRING_FIELDS),
        "numeric_fields": list(NUMERIC_FIELDS),
        "array_fields": list(ARRAY_FIELDS),
        "rule": {"id": "lowercase-slug", "action": "deny", "reason": "one sentence",
                 "all_of": ["one or more predicates; a rule denies when ALL match"]},
        "predicate_forms": [
            {"op": "equals", "field": "<string field>", "value": "<literal>"},
            {"op": "in_set", "field": "<string field>", "values": ["<literal>"]},
            {"op": "at_least", "field": "<numeric field>", "value": 0.75},
            {"op": "present", "field": "<string or numeric field>"},
            {"op": "outside_declared_scope"},
            {"op": "tenant_mismatch"},
        ],
    }, indent=2)


def first_json_object(text: str) -> dict:
    """The first balanced {...} in a model's answer, or {}.

    The Proposer is told to answer with one JSON object and nothing else, and it
    usually does. Finding the object rather than giving up on a stray sentence
    around it is the difference between recording a rejected draft and recording
    nothing at all, and a rejection that goes unrecorded is the failure mode the
    DRAFT-REJECTED link exists to prevent.
    """
    depth = 0
    start = None
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        # Braces inside a JSON string are text, not structure. Counting them
        # ended the object early, so a rationale containing a closing brace
        # turned a valid candidate into a recorded rejection: the model was
        # blamed for the scanner's mistake.
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start:index + 1])
                except json.JSONDecodeError:
                    start = None
    return {}


# --------------------------------------------------------------------------
# The seal, from the Proposer's own side of it
# --------------------------------------------------------------------------

SEALED_DATASET = os.environ.get("CASEHARDEN_SEALED_DATASET", "holdout_sealed")


def self_check(limit: int = 5) -> dict:
    """Try to read the sealed holdout as this process's own identity.

    The Proposer is supposed to want this. Scoring its own draft against the
    exam is exactly what a model asked to write a passing rule would do, and the
    only reason it cannot is that BigQuery refuses the read. So the attempt is
    made for real, and whatever BigQuery answers is what the chain records.

    Returns the refusal. Raises if the read SUCCEEDS, because a Proposer that
    can read the exam invalidates the entry's first claim and must not be
    allowed to look like a pass.
    """
    from caseharden import bq

    table = bq.qualified_table(creds.PROJECT, SEALED_DATASET)
    try:
        rows = bq.query(f"SELECT event_id, label FROM `{table}` LIMIT {int(limit)}",
                        creds.PROJECT, creds.access_token())
    except bq.BigQueryError as exc:
        error = (getattr(exc, "payload", None) or {}).get("error", {})
        return {
            "principal": _identity(),
            "dataset": SEALED_DATASET,
            "permission": "bigquery.tables.getData",
            "http_code": error.get("code"),
            "status": error.get("status"),
            "message": error.get("message") or str(exc),
            "recorded_as": "evidence of what the system refused, not of what it did",
        }
    raise RuntimeError(
        f"the Proposer READ the sealed holdout and got {len(rows)} row(s). "
        "The isolation guarantee this entry rests on is not holding; nothing "
        "should be promoted until the access list is re-sealed.")


def _identity() -> str:
    """Who this process is, as the cloud sees it."""
    return (creds.attached_service_account()
            or f"proposer-sa@{creds.PROJECT}.iam.gserviceaccount.com")


# --------------------------------------------------------------------------
# Precedent
# --------------------------------------------------------------------------

MEMORY_ENGINE = os.environ.get("CASEHARDEN_MEMORY_ENGINE", "")

# Enough for a reviewer's pattern to be visible, short enough that the prompt is
# about this finding rather than about the archive.
MAX_PRECEDENT = 8


def precedent() -> dict:
    """What this fleet has reviewed before, from Vertex AI Memory Bank.

    The ids come back with the facts because the chain's DRAFT link records
    which memories conditioned the draft. Conditioning nobody can name is
    conditioning nobody can check, and section 3 of the plan asks for exactly
    that record.

    An unconfigured engine is reported as unconfigured rather than as an empty
    history: those are different facts and only one of them is about the fleet.
    """
    from agents.common import memory as memory_bank

    if not MEMORY_ENGINE:
        return {"configured": False, "memories": [],
                "note": "no Memory Bank engine is configured for this agent"}
    try:
        stored = memory_bank.read(MEMORY_ENGINE, creds.PROJECT, creds.REGION,
                                  creds.access_token)
    except Exception as exc:
        return {"configured": True, "error": f"{type(exc).__name__}: {exc}"[:300],
                "memories": [],
                "note": "Memory Bank could not be read; this is not an empty history"}
    entries = [{"id": (m.get("name") or "").rsplit("/", 1)[-1],
                "fact": str(m.get("fact", ""))[:1200]}
               for m in stored[-MAX_PRECEDENT:]]
    return {"configured": True, "memories": entries, "count": len(stored)}


# --------------------------------------------------------------------------
# The one corpus the Proposer may read
# --------------------------------------------------------------------------

TRAIN_DATASET = os.environ.get("CASEHARDEN_TRAIN_DATASET", "conduct_train")


def base_rate(field: str, at_least: float) -> dict:
    """How many tool calls in the training window sit at or above a threshold.

    The Proposer holds SELECT on the training window and nothing else, so this
    is the only evidence it can ground a number in. Without it a threshold in a
    draft is a number the model liked; with it, the draft can say how many turns
    the threshold would have covered over 76 days.

    The field is checked against the DSL's own numeric vocabulary rather than
    interpolated as given. Everything the caller controls here is a column name
    from a closed set and a float, so no caller value reaches the SQL as text.
    """
    from caseharden import bq

    if field not in NUMERIC_FIELDS:
        return {"error": f"{field!r} is not a numeric field of the vocabulary",
                "numeric_fields": list(NUMERIC_FIELDS)}
    threshold = float(at_least)
    table = bq.qualified_table(creds.PROJECT, TRAIN_DATASET)
    rows = bq.query(
        f"SELECT COUNT(*) AS turns,"
        f" COUNTIF(tool_name IS NOT NULL) AS tool_calls,"
        f" COUNTIF(tool_name IS NOT NULL AND {field} >= @t) AS at_or_above,"
        f" COUNTIF(tool_name IS NOT NULL AND {field} >= @t AND {field} < 0.75)"
        f"   AS between_here_and_075"
        f" FROM `{table}`",
        creds.PROJECT, creds.access_token(), params={"t": threshold})
    answer = dict(rows[0])
    answer.update({"field": field, "at_least": threshold, "dataset": TRAIN_DATASET,
                   "note": ("the training window carries no labels; these are "
                            "turn counts, not attack counts")})
    return answer
