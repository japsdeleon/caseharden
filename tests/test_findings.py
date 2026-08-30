#!/usr/bin/env python3
"""What the fan-out produces, and what survives it.

The loop asked four detectors and kept one answer. `investigate` built a finding
for the job it picked and dropped the rest: up to three other detectors could
each have found real conduct in the same window, and nothing recorded that they
had. No case, no row, no trace beyond a printed line. A queue built on top of
that would have listed what one run selected rather than what the fleet found.

Each job that returns rows is now a case. The run still asks one question and
still drafts from one finding; the difference is that the others are on the
board for a human instead of gone.

The driver imports cleanly offline — `agents/proposer/draft.py` and
`infra/drive_agent.py` are standard library, `caseharden` and
`agents.common.auth` — so this needs no credential and no stub.

run:  python3 -m pytest tests/test_findings.py -q
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "infra"))

from caseharden import cases  # noqa: E402


def _driver():
    """`infra/110_run_loop.py`, which is a script path rather than a module name."""
    spec = importlib.util.spec_from_file_location(
        "run_loop_under_test", REPO / "infra" / "110_run_loop.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loop = _driver()

WINDOW = ("2026-08-27T09:00:00Z", "2026-08-30T09:00:00Z")


def job(name: str, rows: list) -> dict:
    return {"job_id": f"europe-west3:{name}", "rows": rows}


def finding(name="job_alpha", family="injected-turn", n=3, incident="s_none") -> dict:
    rows = [{"session_id": f"s_{i}", "trace_id": f"t_{i}"} for i in range(n)]
    return loop.build_finding(job(name, rows), family, WINDOW[0], WINDOW[1],
                              incident, "the Foreman's report", "ctx-a")


# --------------------------------------------------------------------------
# One job, as a finding
# --------------------------------------------------------------------------

def test_a_finding_carries_its_own_family_and_job():
    found = finding("job_beta", "cross-tenant", 2)
    assert found["job_id"] == "europe-west3:job_beta"
    assert found["family"] == "cross-tenant"
    assert found["detector"] == "cross-tenant@day5"
    assert found["window_start"], found["window_end"] == WINDOW


def test_sessions_and_traces_are_derived_from_the_rows():
    found = finding(n=3)
    assert found["sessions"] == ["s_0", "s_1", "s_2"]
    assert found["sessions_total"] == 3
    assert found["trace_ids"] == ["t_0", "t_1", "t_2"]


def test_the_row_sample_and_the_lists_are_bounded():
    """The whole finding is hashed and stored, so an unbounded one is a big file."""
    found = finding(n=400)
    assert len(found["rows"]) == 20
    assert len(found["sessions"]) == 200
    assert found["sessions_total"] == 400, "the count is of all of them, not the sample"


def test_citing_the_incident_session_is_per_finding():
    """It was computed once for the chosen job and is now a fact about each."""
    assert finding(n=3, incident="s_1")["cites_incident_session"] is True
    assert finding(n=3, incident="s_99")["cites_incident_session"] is False


# --------------------------------------------------------------------------
# What reaches the store
# --------------------------------------------------------------------------

def test_every_detector_that_found_something_becomes_a_case(tmp_path):
    """The regression this exists for: three findings, three cases, one live."""
    live = finding("job_alpha", "injected-turn", 3)
    others = [finding("job_beta", "cross-tenant", 2),
              finding("job_gamma", "scope-escape", 1)]
    loop.publish_finding(tmp_path, live, [live] + others)

    listed = cases.list_cases(tmp_path / cases.CASES_DIRNAME)
    assert listed["total"] == 3
    assert {c["family"] for c in listed["cases"]} == {
        "injected-turn", "cross-tenant", "scope-escape"}
    # The run still asks about one of them, and that is the one on disk as live.
    written = json.loads((tmp_path / loop.LIVE_FINDING).read_text())
    assert written["job_id"] == live["job_id"]


def test_the_case_the_run_asks_about_is_not_special_in_the_store(tmp_path):
    """A queue sorts them together; nothing marks one as the run's own."""
    live = finding("job_alpha", "injected-turn", 3)
    loop.publish_finding(tmp_path, live, [live, finding("job_beta", "cross-tenant", 2)])
    for row in cases.list_cases(tmp_path / cases.CASES_DIRNAME)["cases"]:
        assert "live" not in row and "under_review" not in row


def test_a_second_run_revises_only_what_changed(tmp_path):
    live = finding("job_alpha", "injected-turn", 3)
    beta = finding("job_beta", "cross-tenant", 2)
    loop.publish_finding(tmp_path, live, [live, beta])
    loop.publish_finding(tmp_path, live, [live, finding("job_beta", "cross-tenant", 9)])

    by_family = {c["family"]: c for c in
                 cases.list_cases(tmp_path / cases.CASES_DIRNAME)["cases"]}
    assert by_family["cross-tenant"]["revisions"] == 1
    assert by_family["injected-turn"]["revisions"] == 0
    assert len(by_family) == 2, "a re-run must not open a second case per job"


def test_a_store_that_will_not_take_one_of_them_refuses_the_run(tmp_path):
    """Partial success is the confusing state; the whole publish is the unit."""
    (tmp_path / cases.CASES_DIRNAME).write_text("not a directory")
    with pytest.raises(SystemExit) as raised:
        loop.publish_finding(tmp_path, finding(), [finding()])
    assert "case store" in str(raised.value)
