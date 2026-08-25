#!/usr/bin/env python3
"""Two evaluators for one grammar: a Python one and a BigQuery compiler.

The Python evaluator is what pytest runs and what the local Examiner uses. The
compiler is what actually scores a candidate against the sealed holdout, because
the holdout lives in BigQuery and only examiner-sa may read it.

Two implementations of one semantics is a divergence risk, so the two are not
trusted to agree. Both compute a digest over the event ids they denied, and
`examiner.py --check-equivalence` runs both over the same corpora and fails if
the digests differ. NULL handling is where they would drift first: in BigQuery a
comparison against NULL is NULL, which is not TRUE, so a row with a NULL field
is not denied. Every predicate below reproduces that rule explicitly.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .dsl import Policy, Rule


# --------------------------------------------------------------------------
# Python evaluation
# --------------------------------------------------------------------------

def _matches(pred, event: dict) -> bool:
    op = pred.op
    if op == "outside_declared_scope":
        tool = event.get("tool_name")
        return tool is not None and tool not in (event.get("declared_scope") or [])
    if op == "tenant_mismatch":
        target, own = event.get("target_tenant_id"), event.get("tenant_id")
        # Both sides explicitly. In BigQuery `x != NULL` is NULL, which is not
        # TRUE, so a NULL tenant_id denies nothing there; Python's `!=` would
        # have said True and the engines would have disagreed on that row.
        return target is not None and own is not None and target != own

    value = event.get(pred.field)
    if value is None:  # NULL compares to nothing, in either engine
        return False
    if op == "present":
        return True
    if op == "equals":
        return value == pred.value
    if op == "in_set":
        return value in pred.values
    if op == "at_least":
        return value >= pred.value
    raise ValueError(f"unhandled predicate: {op}")  # unreachable: dsl.py is closed


def denying_rule(policy: Policy, event: dict) -> Optional[str]:
    """The id of the first rule that denies this turn, or None."""
    for rule in policy.rules:
        if all(_matches(p, event) for p in rule.all_of):
            return rule.id
    return None


def denied_event_ids(policy: Policy, events: Iterable[dict]) -> Set[str]:
    return {e["event_id"] for e in events if denying_rule(policy, e) is not None}


def denied_sessions(policy: Policy, events: Iterable[dict]) -> Set[str]:
    """A session is denied when the policy denies any turn in it.

    Catch rate is session-scored. The abuse is a session-level behaviour and a
    single denied turn stops it, so counting rows would understate the block.
    """
    return {e["session_id"] for e in events if denying_rule(policy, e) is not None}


def digest(event_ids: Iterable[str]) -> str:
    """Order-independent fingerprint of a denial set, comparable across engines."""
    joined = "".join(sorted(event_ids))
    return hashlib.md5(joined.encode()).hexdigest()


# --------------------------------------------------------------------------
# BigQuery compilation
# --------------------------------------------------------------------------

def _literal(value: str) -> str:
    """A single-quoted SQL string.

    dsl.LITERAL_RE already rejects quotes, backslashes and control characters at
    parse time. This escapes anyway: the parse-time check is the boundary that
    matters, and this is the one that has to still be right if that check is
    ever loosened.
    """
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _sql_predicate(pred) -> str:
    op = pred.op
    if op == "outside_declared_scope":
        return "(tool_name IS NOT NULL AND tool_name NOT IN UNNEST(declared_scope))"
    if op == "tenant_mismatch":
        return ("(target_tenant_id IS NOT NULL AND tenant_id IS NOT NULL"
                " AND target_tenant_id != tenant_id)")
    if op == "present":
        return f"({pred.field} IS NOT NULL)"
    if op == "equals":
        return f"({pred.field} = {_literal(pred.value)})"
    if op == "in_set":
        joined = ", ".join(_literal(v) for v in pred.values)
        return f"({pred.field} IN ({joined}))"
    if op == "at_least":
        # dsl.AtLeast rejects non-finite values at parse time. repr() of a finite
        # float is a valid BigQuery FLOAT64 literal; inf and nan are not, and
        # would compile to bare identifiers.
        return f"({pred.field} >= {float(pred.value)!r})"
    raise ValueError(f"unhandled predicate: {op}")


def _sql_rule(rule: Rule) -> str:
    return "(" + " AND ".join(_sql_predicate(p) for p in rule.all_of) + ")"


def structurally_monotonic(candidate: Policy, current: Policy) -> Tuple[bool, List[str]]:
    """Does the candidate narrow authority for every input, not just the ones on hand?

    Replaying two policies over a corpus only proves monotonicity for turns the
    corpus contains. An adversarial pass narrowed the active scope rule with an
    extra predicate no row in either corpus could witness, and the replay said
    the candidate was monotone. It was not.

    This decides it on the policy instead. A rule denies when all of its
    predicates match, so removing predicates broadens a rule and adding them
    narrows it. Candidate rule R' therefore denies everything active rule R
    denies exactly when R's predicate set contains R's own: predicates(R') is a
    subset of predicates(R). If every active rule has such a candidate rule, the
    candidate's denial set is a superset of the active version's on every
    possible input, corpus or no corpus.

    Conservative on purpose: a candidate that expresses the same rule a different
    way is refused rather than analysed. The remedy is to carry the rule forward
    unchanged, which is what a narrowing edit does anyway.

    Returns the verdict and the ids of the active rules nothing covers.
    """
    def keys(rule: Rule) -> set:
        # Compared as canonical JSON: a predicate carrying a list is not hashable
        # as a model, and two predicates are the same predicate when they
        # serialize the same.
        return {json.dumps(p.model_dump(mode="json"), sort_keys=True) for p in rule.all_of}

    uncovered = []
    for rule in current.rules:
        target = keys(rule)
        if not any(keys(c) <= target for c in candidate.rules):
            uncovered.append(rule.id)
    return not uncovered, uncovered


def to_sql_predicate(policy: Policy) -> str:
    """The whole policy as one boolean expression over a turn row."""
    return "(" + "\n     OR ".join(_sql_rule(r) for r in policy.rules) + ")"


def to_sql_scoring_query(policy: Policy, table: str) -> str:
    """Per-label totals for one corpus.

    Aggregated in BigQuery rather than paged out row by row: the Examiner needs
    counts, and a denial set of a few thousand rows is not worth paginating. The
    digest column is what `--check-equivalence` compares against the Python
    evaluator, so it is computed the same way on both sides: md5 over the sorted
    denied event ids with no separator.
    """
    return f"""
WITH scored AS (
  SELECT event_id, session_id, label, amount_cents,
         {to_sql_predicate(policy)} AS denied
  FROM `{table}`
)
SELECT
  IFNULL(label, '<unlabelled>')                              AS label,
  COUNT(*)                                                   AS turns,
  COUNT(DISTINCT session_id)                                 AS sessions,
  COUNTIF(denied)                                            AS denied_turns,
  COUNT(DISTINCT IF(denied, session_id, NULL))               AS denied_sessions,
  IFNULL(SUM(IF(denied, amount_cents, 0)), 0)                AS denied_amount_cents
FROM scored
GROUP BY label
ORDER BY label
""".strip()


def to_sql_digest_query(policy: Policy, table: str) -> str:
    return f"""
SELECT TO_HEX(MD5(IFNULL(STRING_AGG(event_id, '' ORDER BY event_id), ''))) AS denial_digest
FROM `{table}`
WHERE {to_sql_predicate(policy)}
""".strip()


# --------------------------------------------------------------------------
# Local scoring shared by both backends
# --------------------------------------------------------------------------

def tally(policy: Policy, events: Sequence[dict]) -> Dict[str, dict]:
    """The same shape the scoring query returns, computed in Python.

    Keyed by label so the two backends are compared field by field rather than
    on a single total that could match by coincidence.
    """
    out: Dict[str, dict] = {}
    denied_sessions_by_label: Dict[str, set] = {}
    sessions_by_label: Dict[str, set] = {}
    for e in events:
        label = e.get("label") or "<unlabelled>"
        row = out.setdefault(
            label,
            {"label": label, "turns": 0, "sessions": 0, "denied_turns": 0,
             "denied_sessions": 0, "denied_amount_cents": 0},
        )
        sessions_by_label.setdefault(label, set()).add(e["session_id"])
        denied_sessions_by_label.setdefault(label, set())
        row["turns"] += 1
        if denying_rule(policy, e) is not None:
            row["denied_turns"] += 1
            row["denied_amount_cents"] += e.get("amount_cents") or 0
            denied_sessions_by_label[label].add(e["session_id"])
    for label, row in out.items():
        row["sessions"] = len(sessions_by_label[label])
        row["denied_sessions"] = len(denied_sessions_by_label[label])
    return out
