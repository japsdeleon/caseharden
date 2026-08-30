#!/usr/bin/env python3
"""What the Copilot's write path refuses, and what it stores when it does not.

`record_verdict` is the only thing in this fleet that may write a row a chain
will later cite as a human's decision, so what it will not write is the part
worth pinning. Four properties are:

  a verdict with nothing in the rationale is refused, and refused BEFORE Model
  Armor and before the insert. Screening the analyst's words was never a check
  that there were any: an empty rationale screened clean, stored clean, and
  reached the chain as a VERDICT link giving no reason at all.

  a citation is checked for shape and never for existence. This process holds
  `analyst-sa`, which has no read on `policy.versions`; a test that expected it
  to reject an unknown version would be asking it to claim a check it cannot
  make. `tests/test_workbench.py` holds the existence check, at the reader that
  has the identity for it.

  the two patterns the shape check uses are still the ones `caseharden/chain.py`
  registers versions with. They are copied into the agent rather than imported,
  because `infra/33_deploy_copilot.sh` stages three modules by name and importing
  the chain module would ship it into the least trusted container in the fleet.
  A copy that drifts is a citation this repo accepts and the registry refuses.

  a refusal writes nothing. Not a partial row, not a screening result for a
  verdict that does not exist.

ADK is not installed on the offline path this suite runs on, and the agent
module imports `LlmAgent` at import time to build `root_agent`. It is stubbed
below, which is enough: nothing under test is an ADK behaviour. The tools are
plain functions and are called as plain functions.

run:  python3 -m pytest tests -q
"""

from __future__ import annotations

import ast
import importlib.util
import math
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def _load_agent():
    """The Copilot module, with ADK stubbed and no credential touched.

    `creds.guard_ambient()` runs at import. It returns early when `google.auth`
    is absent, which it is here, so importing this module mints nothing and
    reaches no network.
    """
    google = sys.modules.setdefault("google", types.ModuleType("google"))
    adk = types.ModuleType("google.adk")
    agents_mod = types.ModuleType("google.adk.agents")

    class LlmAgent:  # noqa: D401 - a stand-in, not a model
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    agents_mod.LlmAgent = LlmAgent
    adk.agents = agents_mod
    google.adk = adk
    sys.modules["google.adk"] = adk
    sys.modules["google.adk.agents"] = agents_mod

    path = REPO / "agents" / "copilot" / "agent.py"
    spec = importlib.util.spec_from_file_location("caseharden_copilot_agent", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


agent = _load_agent()

JOB = "europe-west3:job_5UcJoBBEaZWU0"
REASON = ("the fleet is taking repeated prompt-injection attempts on tenant t_014 "
          "and the active policy only denies the highest-confidence turns")


@pytest.fixture
def recorded(monkeypatch):
    """Every write and every screening call this test made, and no cloud."""
    seen = {"rows": [], "screened": []}

    def fake_screen(text):
        seen["screened"].append(text)
        return {"ma_verdict": "ALLOW", "ma_band": "NO_MATCH_FOUND",
                "ma_prompt_injection_score": 0.0, "ma_jailbreak_score": 0.0}

    monkeypatch.setattr(agent, "_screen", fake_screen)
    monkeypatch.setattr(agent, "_write", lambda row: seen["rows"].append(row))
    return seen


# --------------------------------------------------------------------------
# the copied patterns
# --------------------------------------------------------------------------

def test_the_shape_check_uses_the_registry_own_patterns():
    from caseharden import chain

    assert agent.VERSION_RE.pattern == chain.VERSION_RE.pattern
    assert agent.LINE_RE.pattern == chain.LINE_RE.pattern


# --------------------------------------------------------------------------
# the rationale floor
# --------------------------------------------------------------------------

@pytest.mark.parametrize("rationale", ["", "   ", "ok", "confirmed", "looks bad"])
def test_a_verdict_with_no_reasoning_is_refused(recorded, rationale):
    out = agent.record_verdict(JOB, "confirmed abuse", rationale)
    assert out["recorded"] is False
    assert "Nothing stored" in out["refused"]
    assert recorded["rows"] == []


def test_a_refusal_costs_no_screening_call(recorded):
    """Refused before Model Armor, so no screening result exists for a row that does not."""
    agent.record_verdict(JOB, "confirmed abuse", "")
    assert recorded["screened"] == []


def test_the_disposition_typed_twice_is_not_a_rationale(recorded):
    """Long enough to pass a length check, and adds nothing the row does not hold."""
    out = agent.record_verdict(JOB, "needs more evidence from payments",
                               "needs more evidence from payments")
    assert out["recorded"] is False
    assert recorded["rows"] == []


def test_the_job_id_alone_is_not_a_rationale(recorded):
    """The compose box prefills the id, and the model rewrites arguments.

    A 40-character job id passes any length check taken over the raw argument,
    which is why the floor is measured on what is left after the id comes out.
    """
    out = agent.record_verdict(JOB, "confirmed abuse", f"  {JOB}  ")
    assert out["recorded"] is False
    assert recorded["rows"] == []


def test_an_empty_rationale_is_refused_as_empty_and_not_as_a_restatement():
    """Both fields blank met the equality test first and named the wrong field.

    The length check runs before it, so an empty rationale is refused for being
    empty rather than for restating an empty disposition.
    """
    with pytest.raises(agent.Refused) as exc:
        agent._own_words_or_refuse("", "", "")
    assert "character(s)" in str(exc.value)


def test_the_floor_is_the_longest_disposition_this_tool_documents():
    """Not a round number: 19 characters is "needs more evidence", so 20 is the floor."""
    assert agent.RATIONALE_MIN_CHARS == len("needs more evidence") + 1


def test_a_verdict_with_reasoning_is_stored_verbatim(recorded):
    out = agent.record_verdict(JOB, "confirmed abuse", REASON)
    assert out["recorded"] is True
    assert recorded["rows"][0]["rationale"] == REASON, (
        "the row must hold what the analyst typed, not the measured remainder")
    assert recorded["screened"] == [REASON]


# --------------------------------------------------------------------------
# the citation
# --------------------------------------------------------------------------

def test_no_citation_is_recorded_as_no_citation(recorded):
    """Absent, and marked absent. Never filled in from whatever is active now."""
    agent.record_verdict(JOB, "confirmed abuse", REASON)
    row = recorded["rows"][0]
    assert row["citation_source"] == "NONE"
    assert row["cited_version"] is None
    assert row["cited_policy_id"] is None


def test_a_line_and_version_are_stored_as_two_columns(recorded):
    out = agent.record_verdict(JOB, "confirmed abuse", REASON,
                               policy_cited="conduct-policy@v5")
    row = recorded["rows"][0]
    assert (row["cited_policy_id"], row["cited_version"]) == ("conduct-policy", "v5")
    assert row["citation_source"] == "ANALYST"
    assert out["cited_version"] == "v5"


def test_a_bare_version_carries_no_line(recorded):
    agent.record_verdict(JOB, "confirmed abuse", REASON, policy_cited="v5")
    row = recorded["rows"][0]
    assert row["cited_version"] == "v5"
    assert row["cited_policy_id"] is None
    assert row["citation_source"] == "ANALYST"


@pytest.mark.parametrize("cited", ["V5", "v5 or v6", "@v5 ", "line@", "a@b@v5"])
def test_a_citation_that_is_not_a_version_name_is_refused(recorded, cited):
    """`@v5` is in the list on purpose: the analyst reached for a line and named
    none, and normalising that to a bare version files the citation under a line
    nobody wrote."""
    out = agent.record_verdict(JOB, "confirmed abuse", REASON, policy_cited=cited)
    assert out["recorded"] is False
    assert recorded["rows"] == []


def test_a_bad_policy_line_name_is_refused(recorded):
    out = agent.record_verdict(JOB, "confirmed abuse", REASON,
                               policy_cited="Conduct Policy@v5")
    assert out["recorded"] is False
    assert recorded["rows"] == []


def test_an_unknown_version_is_stored_not_refused(recorded):
    """The one thing this identity must not pretend to have checked.

    `analyst-sa` holds WRITER on `review` and no read on `policy`, so it cannot
    tell `v99` from `v5`. Refusing here would be a check nothing made. The row
    stores what the analyst said and the console, holding notary-sa, is where it
    meets the registry.
    """
    out = agent.record_verdict(JOB, "confirmed abuse", REASON, policy_cited="v99")
    assert out["recorded"] is True
    assert recorded["rows"][0]["cited_version"] == "v99"


def test_the_copilot_reads_nothing_to_validate_the_citation():
    """The tempting fix, refused in the source rather than in a promise.

    Validating a citation for real needs the version registry, and the obvious
    way to get it is to widen `analyst-sa` and query from here. THREATS.md
    Not covered 2 is why that trade is refused: whatever this surface can reach
    is reachable by a person typing into a text box.

    So the module must hold no read. It imports `bq` for the insert and must not
    import the chain module, and it must issue no query: `bq.query` is the only
    read path in this repository, and the Copilot calls `bq.insert_rows` alone.
    """
    source = (REPO / "agents" / "copilot" / "agent.py").read_text()
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(f"{node.module}.{a.name}" for a in node.names)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    assert "caseharden.chain" not in imported
    assert "caseharden.bq" in imported

    called = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert "bq.insert_rows" in called
    assert not [c for c in called if c.startswith("bq.") and c != "bq.insert_rows"], (
        f"the Copilot calls BigQuery for something other than its one insert: {called}")


# --------------------------------------------------------------------------
# the advisory, as displayed
# --------------------------------------------------------------------------

def test_no_advisory_is_three_nulls(recorded):
    """Nothing in this repository produces one, so this is every row today."""
    agent.record_verdict(JOB, "confirmed abuse", REASON)
    row = recorded["rows"][0]
    assert row["advisory_recommendation"] is None
    assert row["advisory_rule"] is None
    assert row["advisory_confidence"] is None


def test_an_advisory_is_stored_exactly_as_it_was_passed(recorded):
    agent.record_verdict(JOB, "confirmed abuse", REASON,
                         advisory_recommendation="confirmed abuse",
                         advisory_rule="tool-call-on-injected-turn",
                         advisory_confidence=0.82)
    row = recorded["rows"][0]
    assert row["advisory_recommendation"] == "confirmed abuse"
    assert row["advisory_rule"] == "tool-call-on-injected-turn"
    assert row["advisory_confidence"] == 0.82


def test_a_rule_or_a_number_with_no_recommendation_is_refused(recorded):
    """A record saying the machine was 0.8 confident of nothing cannot be read later."""
    for kwargs in ({"advisory_rule": "r-1"}, {"advisory_confidence": 0.8}):
        out = agent.record_verdict(JOB, "confirmed abuse", REASON, **kwargs)
        assert out["recorded"] is False
    assert recorded["rows"] == []


@pytest.mark.parametrize("confidence", [1.5, -0.5, float("nan"), float("inf")])
def test_a_confidence_outside_the_unit_interval_is_refused(recorded, confidence):
    out = agent.record_verdict(JOB, "confirmed abuse", REASON,
                               advisory_recommendation="benign",
                               advisory_confidence=confidence)
    assert out["recorded"] is False
    assert recorded["rows"] == []


def test_an_advisory_with_no_number_is_allowed(recorded):
    """-1.0 is the absent value: the tool declaration takes a plain float."""
    out = agent.record_verdict(JOB, "confirmed abuse", REASON,
                               advisory_recommendation="benign")
    assert out["recorded"] is True
    assert recorded["rows"][0]["advisory_confidence"] is None


# --------------------------------------------------------------------------
# the untouched half
# --------------------------------------------------------------------------

def test_the_row_still_carries_everything_it_carried_before(recorded):
    """The new columns are additions. Nothing that fed the Notary moved."""
    agent.record_verdict(JOB, "confirmed abuse", REASON)
    row = recorded["rows"][0]
    for column in ("decision_id", "ts", "kind", "analyst", "subject", "disposition",
                   "rationale", "ma_verdict", "ma_band", "ma_prompt_injection_score",
                   "ma_jailbreak_score", "approved"):
        assert column in row
    assert row["kind"] == "VERDICT"
    assert row["subject"] == JOB
    assert row["disposition"] == "confirmed abuse"


def test_an_approval_says_it_cites_nothing_rather_than_leaving_it_blank(recorded):
    """An approval cites no policy and is shown no advisory, and now says so.

    It carried neither column, so the row stored NULL in both. A NULL source is
    documented as a row written before these columns existed, so every approval
    written after the migration dated itself to before it. The values are not a
    citation and not an advisory; they are the record stating that there is
    neither, which is a different fact from an absence.
    """
    agent.approve("v6", True, "the gate passed on all three legs and the parent attests")
    row = recorded["rows"][0]
    assert row["kind"] == "APPROVAL"
    assert row["citation_source"] == "NONE"
    assert row["advisory_source"] == "NONE"
    # The columns that would restate the subject or claim a recommendation stay
    # out: an approval's subject is the version already.
    for absent in ("cited_policy_id", "cited_version", "advisory_recommendation",
                   "advisory_rule", "advisory_confidence"):
        assert absent not in row


def test_nan_is_not_treated_as_absent():
    """`confidence != -1.0` is true for NaN, and the range test then refuses it."""
    with pytest.raises(agent.Refused):
        agent._advisory("benign", "", math.nan)


# --------------------------------------------------------------------------
# What an adversarial pass reached, and what a model can actually send
# --------------------------------------------------------------------------

def test_a_rationale_of_invisible_characters_is_refused(recorded):
    """Twenty zero-width spaces cleared the floor and stored a verdict with no words.

    `strip()` does not remove U+200B and `len()` counts it, so the check that a
    rationale exists was passed by a rationale nobody can read.
    """
    out = agent.record_verdict(JOB, "confirmed abuse", "​" * 40)
    assert out["recorded"] is False
    assert recorded["rows"] == []


@pytest.mark.parametrize("rationale", ["\t" * 40, "\n" * 40, " " * 40,
                                       "​‍﻿" * 20])
def test_whitespace_and_format_characters_are_not_words(recorded, rationale):
    out = agent.record_verdict(JOB, "confirmed abuse", rationale)
    assert out["recorded"] is False
    assert recorded["rows"] == []


def test_a_rationale_with_spaces_between_words_still_counts_them():
    """Spaces have a glyph. Dropping them would raise the floor above its derivation."""
    assert agent._own_words_or_refuse("a b c d e f g h i j k", JOB, "confirmed abuse")


@pytest.mark.parametrize("kwargs", [
    {"policy_cited": 5},
    {"policy_cited": ["v5"]},
    {"advisory_recommendation": 1.0},
    {"advisory_rule": {"id": "r"}},
    {"advisory_confidence": "not a number"},
])
def test_an_argument_of_the_wrong_type_is_a_refusal_not_an_exception(recorded, kwargs):
    """A model sends JSON null or a number for a parameter declared string.

    A raised exception reaches the model as a tool failure, which it retries; the
    instruction only holds if a bad argument comes back as `recorded: false`.
    """
    out = agent.record_verdict(JOB, "confirmed abuse", REASON, **kwargs)
    assert out["recorded"] is False
    assert recorded["rows"] == []


@pytest.mark.parametrize("kwargs", [
    {"policy_cited": None},
    {"advisory_recommendation": None, "advisory_rule": None,
     "advisory_confidence": None},
])
def test_none_reads_as_absent_and_not_as_an_error(recorded, kwargs):
    """That is how an omitted optional argument arrives."""
    out = agent.record_verdict(JOB, "confirmed abuse", REASON, **kwargs)
    assert out["recorded"] is True
    assert recorded["rows"][0]["citation_source"] == "NONE"


def test_a_confidence_sent_as_a_string_is_taken_as_the_number_it_spells(recorded):
    agent.record_verdict(JOB, "confirmed abuse", REASON,
                         advisory_recommendation="benign", advisory_confidence="0.8")
    assert recorded["rows"][0]["advisory_confidence"] == 0.8


def test_a_rationale_that_is_not_text_is_refused(recorded):
    out = agent.record_verdict(JOB, "confirmed abuse", 12345)
    assert out["recorded"] is False
    assert recorded["rows"] == []


# --------------------------------------------------------------------------
# Who asserted the advisory
# --------------------------------------------------------------------------

def test_an_advisory_is_attributed_to_the_surface_that_passed_it(recorded):
    """Nothing in the fleet emits a recommendation, so nothing else is honest.

    Without this the console said "the machine advised X, as it was displayed
    beside this verdict" about a value the recording surface supplied, which
    lets an analyst attribute their own call to a recommendation that never
    existed.
    """
    agent.record_verdict(JOB, "confirmed abuse",
                         "the sessions cited show a real cross-tenant pattern",
                         advisory_recommendation="confirmed abuse",
                         advisory_rule="tool-call-on-injected-turn",
                         advisory_confidence=0.82)
    row = recorded["rows"][0]
    assert row["advisory_source"] == "SURFACE"
    assert row["advisory_recommendation"] == "confirmed abuse"


def test_no_advisory_is_recorded_as_none_not_as_nothing(recorded):
    """NONE and NULL are different: NULL is documented as predating the column."""
    agent.record_verdict(JOB, "benign",
                         "the check fired on a scheduled export job")
    assert recorded["rows"][0]["advisory_source"] == "NONE"


def test_the_surface_cannot_label_itself_a_recommender():
    """A surface that could choose its own provenance label has none.

    `RECOMMENDER` is reserved for a component that emits the triple itself. The
    tool takes no source argument, so there is no path by which a caller reaches
    that value; this pins the absence of one.
    """
    import inspect

    assert "source" not in inspect.signature(agent.record_verdict).parameters
    for shown in ("confirmed abuse", "benign", ""):
        *_, source = agent._advisory(shown, "", -1.0)
        assert source in ("SURFACE", "NONE")
        assert source != "RECOMMENDER"


def test_a_rule_or_a_confidence_without_a_recommendation_is_still_refused():
    """The source must not become a way to record an unattributed fragment."""
    with pytest.raises(agent.Refused):
        agent._advisory("", "tool-call-on-injected-turn", -1.0)
    with pytest.raises(agent.Refused):
        agent._advisory("", "", 0.5)
