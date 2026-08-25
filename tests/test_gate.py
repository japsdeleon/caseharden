#!/usr/bin/env python3
"""The promotion gate, pinned before any agent exists.

The three that matter, in the order the plan states them:

  an over-blocking candidate must FAIL the gate
  a widening candidate must FAIL monotonicity
  a good candidate must PASS

The rest are grammar properties the demo asserts out loud, so they are tested
rather than claimed: there is no allow verb, the answer key is not addressable,
and a string literal cannot carry SQL.

run:  python3 -m pytest tests -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "generator"))

import generate_conduct  # noqa: E402
from caseharden import dsl  # noqa: E402
from caseharden import bq  # noqa: E402
from caseharden.examiner import Score, gate, monotonic, score_local  # noqa: E402
from caseharden.interpreter import (  # noqa: E402
    denied_event_ids,
    denying_rule,
    structurally_monotonic,
    to_sql_predicate,
)

CORPORA, _ = generate_conduct.generate()
REPLAY = CORPORA["benign_corpus"] + CORPORA["holdout_sealed"]

ACTIVE = dsl.load(str(REPO / "policies" / "v3-active.json"))
OVER_BLOCKING = dsl.load(str(REPO / "policies" / "v4-candidate-a.json"))
GOOD = dsl.load(str(REPO / "policies" / "v4-candidate-b.json"))
WIDENING = dsl.load(str(REPO / "policies" / "v4-candidate-widening.json"))


def run_gate(candidate):
    monotone, uncovered = structurally_monotonic(candidate, ACTIVE)
    _, widened = monotonic(candidate, ACTIVE, REPLAY)
    return gate(score_local(candidate, CORPORA), score_local(ACTIVE, CORPORA),
                monotone, uncovered, widened)


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

def test_over_blocking_candidate_is_denied():
    """A better catch rate does not buy a promotion.

    This candidate loses no ground on any family and catches more attacks
    overall. It is refused anyway, because it denies a third of legitimate
    traffic, and that is the whole reason the gate has two sides.
    """
    verdict = run_gate(OVER_BLOCKING)
    assert not verdict.passed
    assert verdict.reason == "BENIGN REGRESSION"
    candidate, active = score_local(OVER_BLOCKING, CORPORA), score_local(ACTIVE, CORPORA)
    # The docstring's claim, asserted rather than described. Without this the
    # test passes even when the candidate has lost a whole family.
    assert all(candidate.caught(f)[0] >= active.caught(f)[0] for f in candidate.families)
    assert candidate.attacks_caught > active.attacks_caught
    assert candidate.benign_pass_rate < 0.70
    # The fourth Examiner output: what the false positives would have cost.
    assert candidate.false_positive_cost_cents == 200711
    assert active.false_positive_cost_cents == 0


def test_widening_candidate_fails_monotonicity():
    """A candidate that re-allows what the active version denies is refused.

    It scores better on attacks and denies no legitimate traffic. It still
    fails, because it drops the scope rule and so widens authority.
    """
    verdict = run_gate(WIDENING)
    assert not verdict.passed
    assert verdict.reason == "AUTHORITY WIDENED"
    monotone, uncovered = structurally_monotonic(WIDENING, ACTIVE)
    assert not monotone and uncovered == ["out-of-declared-scope"]
    _, widened = monotonic(WIDENING, ACTIVE, REPLAY)
    assert widened > 0


def test_a_widening_the_corpus_cannot_witness_is_still_refused():
    """Why monotonicity is decided on the policy and not by replaying rows.

    This candidate keeps the active scope rule and adds one predicate to it, so
    it denies strictly less. Every out-of-scope call in both corpora happens to
    be an `issue_refund`, so no row witnesses the difference and the replay
    reports the candidate as monotone. The structural check does not need a
    witness.
    """
    narrowed = dsl.parse({
        "version": "v4x", "parent": "v3",
        "rules": [
            {"id": "out-of-declared-scope", "action": "deny", "reason": "narrowed",
             "all_of": [{"op": "outside_declared_scope"},
                        {"op": "in_set", "field": "tool_name", "values": ["issue_refund"]}]},
            {"id": "cross-tenant-tool-call", "action": "deny", "reason": "x",
             "all_of": [{"op": "present", "field": "tool_name"}, {"op": "tenant_mismatch"}]},
        ],
    })
    replayed, widened = monotonic(narrowed, ACTIVE, REPLAY)
    assert replayed and widened == 0, "expected the blind spot this check exists to cover"
    monotone, uncovered = structurally_monotonic(narrowed, ACTIVE)
    assert not monotone and uncovered == ["out-of-declared-scope"]
    assert run_gate(narrowed).reason == "AUTHORITY WIDENED"


def test_good_candidate_passes():
    verdict = run_gate(GOOD)
    assert verdict.passed, verdict.reason
    assert all(ok for _, ok, _ in verdict.checks)
    candidate = score_local(GOOD, CORPORA)
    assert candidate.benign_denied == 0
    assert candidate.caught("injected-turn-tool-call")[0] == 9


def test_a_candidate_that_loses_a_family_is_refused():
    """CATCH is per family, not only in total.

    Summed, a candidate that gives up one family and picks up a larger one reads
    as an improvement.
    """
    class _Fake(Score):
        def __init__(self, per_family, benign_turns=640):
            self._per = per_family
            self._benign = benign_turns

        @property
        def families(self):
            return sorted(self._per)

        def caught(self, family):
            return self._per.get(family, (0, 10))

        @property
        def attacks_caught(self):
            return sum(v[0] for v in self._per.values())

        @property
        def attacks_total(self):
            return sum(v[1] for v in self._per.values())

        @property
        def benign_turns(self):
            return self._benign

        @property
        def benign_denied(self):
            return 0

        @property
        def benign_pass_rate(self):
            return 1.0

        @property
        def false_positive_cost_cents(self):
            return 0

    active = _Fake({"a": (10, 10), "b": (0, 10)})
    candidate = _Fake({"a": (1, 10), "b": (10, 10)})  # 10 -> 11 in total, -9 on family a
    verdict = gate(candidate, active, True, [], 0)
    assert not verdict.passed
    assert verdict.reason == "CATCH REGRESSION ON A FAMILY"


def test_an_empty_corpus_does_not_pass_the_benign_leg():
    """A query that returned nothing is not a corpus nobody denied.

    jobs.query answers a timeout with no rows and no error. Read as a score that
    is a 100 percent benign pass rate, and the over-blocking candidate promotes.
    """
    empty = Score(OVER_BLOCKING, {}, {})
    verdict = gate(empty, score_local(ACTIVE, CORPORA), True, [], 0)
    assert not verdict.passed
    assert verdict.reason == "NO EVIDENCE SCORED"


def test_monotonicity_over_the_benign_corpus_alone_is_vacuous():
    """Why the replay corpus is the benign corpus AND the holdout.

    The active version denies nothing in the benign corpus, so every candidate
    is trivially a superset there, including the one that widens authority. The
    check only measures something once the replay corpus contains turns the
    active version denies.
    """
    assert denied_event_ids(ACTIVE, CORPORA["benign_corpus"]) == set()
    benign_only, _ = monotonic(WIDENING, ACTIVE, CORPORA["benign_corpus"])
    assert benign_only, "expected the vacuous pass this corpus choice avoids"
    with_holdout, _ = monotonic(WIDENING, ACTIVE, REPLAY)
    assert not with_holdout


# --------------------------------------------------------------------------
# Grammar properties the demo states out loud
# --------------------------------------------------------------------------

def test_there_is_no_allow_verb():
    with pytest.raises(ValidationError):
        dsl.parse({"version": "v9", "rules": [{"id": "widen", "action": "allow",
                                               "reason": "x",
                                               "all_of": [{"op": "tenant_mismatch"}]}]})


def test_unknown_predicate_is_rejected_by_name():
    with pytest.raises(ValidationError) as exc:
        dsl.parse({"version": "v9", "rules": [{"id": "guess", "action": "deny", "reason": "x",
                                               "all_of": [{"op": "looks_suspicious"}]}]})
    assert "looks_suspicious" in str(exc.value)


def test_the_answer_key_is_not_addressable():
    """A candidate cannot cite the label even if handed a labelled row."""
    for field in generate_conduct.ANSWER_KEY_FIELDS + ("session_id",):
        with pytest.raises(ValidationError):
            dsl.parse({"version": "v9", "rules": [{"id": "cheat", "action": "deny", "reason": "x",
                                                   "all_of": [{"op": "present", "field": field}]}]})


def test_an_identifier_is_not_addressable():
    """A candidate cannot name the accounts in the exam.

    A set of per-call account ids catches a whole family, denies nothing
    legitimate, passes all three legs and generalizes to nothing.
    """
    with pytest.raises(ValidationError):
        dsl.parse({"version": "v9", "rules": [{"id": "replay-ids", "action": "deny",
                                               "reason": "x",
                                               "all_of": [{"op": "in_set", "field": "account_id",
                                                           "values": ["a_471014"]}]}]})


def test_a_threshold_must_be_a_finite_number():
    """1e400 is valid JSON, parses to inf, and compiles to a bare identifier."""
    for bad in ("NaN", "Infinity", 1e400, float("nan"), True):
        with pytest.raises(ValidationError):
            dsl.parse({"version": "v9", "rules": [{"id": "threshold", "action": "deny",
                                                   "reason": "x",
                                                   "all_of": [{"op": "at_least",
                                                               "field": "amount_cents",
                                                               "value": bad}]}]})


def test_a_backtick_cannot_reach_a_table_identifier():
    """--project and CASEHARDEN_PROJECT are interpolated into SQL and a URL."""
    with pytest.raises(ValueError):
        bq.qualified_table("victim` WHERE TRUE --", "holdout_sealed")
    assert bq.qualified_table("devpost-hackathon-506416", "holdout_sealed") == (
        "devpost-hackathon-506416.holdout_sealed.turns"
    )


# --------------------------------------------------------------------------
# The compiler, which the suite otherwise never reaches
# --------------------------------------------------------------------------

def test_every_predicate_compiles_to_null_safe_sql():
    """One grammar, two engines. NULL is where they would drift first."""
    expected = {
        "outside_declared_scope":
            "(tool_name IS NOT NULL AND tool_name NOT IN UNNEST(declared_scope))",
        "tenant_mismatch":
            "(target_tenant_id IS NOT NULL AND tenant_id IS NOT NULL "
            "AND target_tenant_id != tenant_id)",
        "present": "(tool_name IS NOT NULL)",
        "equals": "(tool_name = 'issue_refund')",
        "in_set": "(tool_name IN ('issue_refund', 'lookup_account'))",
        "at_least": "(ma_prompt_injection_score >= 0.75)",
    }
    predicates = {
        "outside_declared_scope": {"op": "outside_declared_scope"},
        "tenant_mismatch": {"op": "tenant_mismatch"},
        "present": {"op": "present", "field": "tool_name"},
        "equals": {"op": "equals", "field": "tool_name", "value": "issue_refund"},
        "in_set": {"op": "in_set", "field": "tool_name",
                   "values": ["issue_refund", "lookup_account"]},
        "at_least": {"op": "at_least", "field": "ma_prompt_injection_score", "value": 0.75},
    }
    # Every predicate the grammar has, read off the grammar itself, so adding a
    # predicate without compiling it here fails rather than going unnoticed.
    assert set(predicates) == set(dsl.PREDICATE_OPS) == set(expected)
    for op, body in predicates.items():
        policy = dsl.parse({"version": "v9", "rules": [{"id": "compile-me", "action": "deny",
                                                        "reason": "x", "all_of": [body]}]})
        assert to_sql_predicate(policy) == f"(({expected[op]}))"


def test_the_two_engines_agree_on_a_null_tenant():
    """A row Python denied and BigQuery would not, before the fix."""
    policy = dsl.parse({"version": "v9", "rules": [{"id": "cross-tenant", "action": "deny",
                                                    "reason": "x",
                                                    "all_of": [{"op": "tenant_mismatch"}]}]})
    row = {"event_id": "e1", "session_id": "s1", "target_tenant_id": "t_002", "tenant_id": None}
    assert denying_rule(policy, row) is None
    assert "tenant_id IS NOT NULL" in to_sql_predicate(policy)


def test_the_vocabulary_matches_the_corpus():
    """One list, two files. A drift here is a column no candidate can use."""
    assert dsl.PREDICATE_FIELDS == tuple(sorted(generate_conduct.PREDICATE_FIELDS))


def test_a_literal_cannot_carry_sql():
    with pytest.raises(ValidationError):
        dsl.parse({"version": "v9", "rules": [{"id": "inject", "action": "deny", "reason": "x",
                                               "all_of": [{"op": "equals", "field": "tool_name",
                                                           "value": "x' OR '1'='1"}]}]})
