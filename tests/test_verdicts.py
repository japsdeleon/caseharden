#!/usr/bin/env python3
"""The verdict taxonomy, and the two places it has to hold.

The defect these pin: `record_verdict` took any string as the analyst's
disposition and `infra/110_run_loop.py` drafted a policy from any VERDICT row,
so "needs more evidence" produced a candidate policy version. Three properties
close it and each fails on a plausible simplification.

  exactly one member drafts. Widening that to "anything the taxonomy
  recognises" puts `benign` back on the drafting path, which is the original
  defect with a smaller vocabulary.

  a phrase outside the set is refused, never mapped to the nearest member.
  "false positive" reads as `benign` to a human and a caller that acts on that
  reading has conducted the review.

  the model sees the same four the code enforces. A tool whose argument is
  constrained but whose docstring still offers free phrasing fights itself: the
  model writes what the docstring taught it and the tool refuses every call.

Both surfaces are driven for real. `infra/110_run_loop.py` imports nothing
outside this repo and the standard library. The Copilot needs `google.adk`,
which is the container's dependency and not in `requirements-verify.txt`, so the
one class it constructs is stood in for; see the `copilot` fixture for the other
thing that import needs and why it is given rather than worked around.

run:  python3 -m pytest tests/test_verdicts.py -q
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "infra"))

from caseharden import verdicts  # noqa: E402

COPILOT = REPO / "agents" / "copilot" / "agent.py"


# --------------------------------------------------------------------------
# The taxonomy
# --------------------------------------------------------------------------

def test_exactly_one_member_drafts():
    assert verdicts.DRAFTS not in verdicts.TERMINAL
    assert set(verdicts.MEMBERS) == {verdicts.DRAFTS} | set(verdicts.TERMINAL)
    assert len(verdicts.MEMBERS) == len(set(verdicts.MEMBERS))
    # Every member is spelled out somewhere a person reads, so a member added
    # without a meaning cannot reach the Copilot's refusal as a bare string.
    assert set(verdicts.MEANING) == set(verdicts.MEMBERS)


def test_the_three_answers_that_are_not_confirmations_are_terminal():
    """The ticket's three: nothing found, cannot tell, not my call."""
    for said in ("benign", "insufficient evidence", "escalate"):
        called = verdicts.member(said)
        assert called is not None, said
        assert called != verdicts.DRAFTS, said


def test_case_and_spacing_are_not_meaning():
    for said in ("Confirmed Abuse", "  confirmed   abuse ", "CONFIRMED ABUSE",
                 "confirmed\tabuse", "Insufficient Evidence"):
        assert verdicts.member(said) in verdicts.MEMBERS, said
    # And the canonical spelling comes back, so one review reads one way in the
    # table whatever the analyst's shift key was doing.
    assert verdicts.member("Confirmed  Abuse") == "confirmed abuse"


def test_a_near_synonym_is_refused_and_not_mapped():
    """Each of these means a member to a human. None of them is one."""
    for said in ("false positive", "needs more evidence", "not established",
                 "no action", "confirmed", "abuse", "benign activity",
                 "confirmed_abuse", "confirmed abuse.", "escalated"):
        assert verdicts.member(said) is None, said


def test_nothing_is_not_a_member_either():
    for said in ("", "   ", None):
        assert verdicts.member(said) is None


def test_the_offer_names_every_member():
    line = verdicts.offer()
    for m in verdicts.MEMBERS:
        assert m in line


# --------------------------------------------------------------------------
# What the Copilot's model is told
# --------------------------------------------------------------------------

@pytest.fixture
def copilot(monkeypatch):
    """`agents/copilot/agent.py`, imported with its two cloud edges stood in for.

    `google.adk` ships in the container and is not in requirements-verify.txt,
    so the one class this module constructs is a stand-in here.

    `K_SERVICE` is set because `creds.guard_ambient` runs at import and, off
    Cloud Run, reads Application Default Credentials. On the workstation this
    repo is built on those are an employer's, and the module is supposed to
    refuse to start under them. That refusal is the point of `creds.py`, so the
    test says it is in a container rather than handing the guard a credential to
    approve.

    `sys.path` is restored afterwards: the module puts its own directory on the
    path so the same source runs from the folder `adk deploy` ships.
    """
    stand_in = types.ModuleType("google.adk.agents")

    class LlmAgent:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    stand_in.LlmAgent = LlmAgent
    package = types.ModuleType("google.adk")
    package.agents = stand_in
    monkeypatch.setitem(sys.modules, "google.adk", package)
    monkeypatch.setitem(sys.modules, "google.adk.agents", stand_in)
    monkeypatch.setenv("K_SERVICE", "copilot-under-test")
    monkeypatch.setattr(sys, "path", list(sys.path))

    spec = importlib.util.spec_from_file_location("copilot_under_test", COPILOT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def stored(copilot, monkeypatch):
    """Every row record_verdict wrote, and a screening that always allows."""
    rows = []
    monkeypatch.setattr(copilot, "_write", rows.append)
    monkeypatch.setattr(copilot, "_screen",
                        lambda text: {"ma_verdict": "ALLOW", "ma_band": "NONE"})
    return rows


def test_a_disposition_outside_the_taxonomy_stores_nothing(copilot, stored):
    """Refused where the analyst can still fix it, not stored as free text."""
    answer = copilot.record_verdict("job_x", "false positive", "the sessions cited show a real pattern")
    assert answer["recorded"] is False
    assert stored == []
    assert set(answer["choices"]) == set(verdicts.MEMBERS)
    assert "false positive" in answer["error"]


def test_a_refusal_reaches_no_cloud_service_at_all(copilot, monkeypatch):
    """Neither Model Armor nor BigQuery is called for a value nothing can read."""
    def refuse(*a, **k):
        raise AssertionError("a refused disposition called out to a service")

    monkeypatch.setattr(copilot, "_write", refuse)
    monkeypatch.setattr(copilot, "_screen", refuse)
    assert copilot.record_verdict("job_x", "", "the sessions cited show a real pattern")["recorded"] is False


def test_a_member_is_stored_under_its_own_spelling(copilot, stored):
    answer = copilot.record_verdict("job_x", "  Confirmed  Abuse ", "the sessions cited show a real pattern")
    assert answer["recorded"] is True
    assert stored[0]["disposition"] == verdicts.DRAFTS
    assert stored[0]["kind"] == "VERDICT"
    # The analyst's own words are untouched. Only the control value is folded.
    assert stored[0]["rationale"] == "the sessions cited show a real pattern"


def test_every_member_is_recordable(copilot, stored):
    for m in verdicts.MEMBERS:
        assert copilot.record_verdict("job_x", m, "the sessions cited show a real pattern")["recorded"] is True
    assert [r["disposition"] for r in stored] == list(verdicts.MEMBERS)


def test_the_tool_the_model_reads_names_the_four_it_enforces(copilot):
    doc = copilot.record_verdict.__doc__
    for m in verdicts.MEMBERS:
        assert f'"{m}"' in doc, m


def test_the_tool_no_longer_offers_a_phrasing_it_would_refuse(copilot):
    """The docstring's examples were "false positive" and "needs more evidence".

    A tool whose argument is constrained and whose docstring still teaches the
    model two refused values refuses every call the model makes.
    """
    doc = copilot.record_verdict.__doc__
    for refused in ("false positive", "needs more evidence"):
        assert f'"{refused}"' not in doc, refused


def test_the_instruction_names_the_four_and_what_a_refusal_means(copilot):
    text = copilot.root_agent.instruction
    for m in verdicts.MEMBERS:
        assert f"'{m}'" in text, m
    assert "recorded=false" in text.lower()


# --------------------------------------------------------------------------
# The branch in the driver
# --------------------------------------------------------------------------

ACTIVE = {
    "version": "v4",
    "rules": [
        {"id": "cross-tenant-tool-call", "action": "deny", "reason": "egress",
         "all_of": [{"op": "present", "field": "tool_name"},
                    {"op": "tenant_mismatch"}]},
    ],
}

FINDING = {
    "family": "cross-tenant",
    "job_id": "europe-west3:job_5UcJoBBEaZWU0",
    "window_start": "2026-08-30T00:00:00Z",
    "window_end": "2026-08-30T01:00:00Z",
    "sessions": ["s1"],
    "rows": [{"session_id": "s1"}],
}


class Drafted(Exception):
    """Raised in place of draft_loop, so reaching it is visible and cheap."""


def run_loop():
    """Import infra/110_run_loop.py. Its name is not an identifier."""
    path = REPO / "infra" / "110_run_loop.py"
    spec = importlib.util.spec_from_file_location("run_loop_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def drive(monkeypatch, tmp_path, disposition: str):
    """Run main() up to the verdict branch and no further.

    Everything before the branch is a call to the fleet or the warehouse, so it
    is answered here: the version registry, the fan-out, and the row a human
    would have typed. `draft_loop` raises, so a candidate being drafted is a
    distinguishable outcome rather than a network timeout.
    """
    loop = run_loop()

    class Store:
        def __init__(self, *a, **k):
            pass

        def versions(self):
            return [{"version": "v4", "policy": json.dumps(ACTIVE)}]

    import caseharden.chain

    monkeypatch.setattr(caseharden.chain, "ChainStore", Store)
    monkeypatch.setattr(loop.bq, "access_token", lambda *a, **k: "t")
    # `(live, findings)` since the loop stopped discarding the jobs it did not
    # pick. One finding here: this file is about what the disposition does to the
    # run, not about how many cases the fan-out opens.
    monkeypatch.setattr(loop, "investigate",
                        lambda *a, **k: (dict(FINDING), [dict(FINDING)]))
    monkeypatch.setattr(loop, "wait_for", lambda *a, **k: {
        "decision_id": "vd_deadbeef", "analyst": "analyst@caseharden.example",
        "disposition": disposition, "rationale": "because", "ts": "now",
        "ma_verdict": "ALLOW", "ma_band": "NO_MATCH_FOUND",
    })

    def drafted(*a, **k):
        raise Drafted()

    monkeypatch.setattr(loop, "draft_loop", drafted)
    return loop.main(["--version", "v6", "--parent", "v4", "--skip-incident",
                      "--out", str(tmp_path)])


@pytest.mark.parametrize("disposition", verdicts.TERMINAL)
def test_a_terminal_verdict_never_reaches_the_proposer(monkeypatch, tmp_path,
                                                       disposition, capsys):
    """The defect. Every VERDICT row used to draft a candidate policy."""
    assert drive(monkeypatch, tmp_path, disposition) == 0
    assert "closes here" in capsys.readouterr().out


def test_a_confirmation_still_drafts(monkeypatch, tmp_path):
    """The branch has to let the loop's whole reason for existing through."""
    with pytest.raises(Drafted):
        drive(monkeypatch, tmp_path, verdicts.DRAFTS)


def test_a_terminal_verdict_closes_rather_than_fails(monkeypatch, tmp_path):
    """Zero, not a raise. A finding reviewed and closed is an outcome.

    The repo already treats a refusal as a first-class result rather than an
    error, and the verdict is on the record in `review.decisions` before this
    point, so there is nothing left to report as a failure.
    """
    assert drive(monkeypatch, tmp_path, "benign") == 0


def test_a_disposition_the_taxonomy_does_not_know_stops_the_run(monkeypatch,
                                                                tmp_path):
    """Free text is not read as the nearest member, and is not drafted from.

    Rows written before the taxonomy existed reach here. `unknown` about
    attestation freezes promotion rather than guessing at a state, and this is
    the same answer about a review.
    """
    with pytest.raises(SystemExit) as raised:
        drive(monkeypatch, tmp_path, "false positive")
    said = str(raised.value)
    assert "false positive" in said
    assert "review.decisions" in said
    for m in verdicts.MEMBERS:
        assert m in said, m
