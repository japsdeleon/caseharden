#!/usr/bin/env python3
"""The case store, pinned to the four properties a queue depends on.

A queue that sorts by age, links to a case and shows whether its evidence moved
is reading facts this module wrote. Each of these tests fails on a plausible
simplification of it:

  the same detector job is one case, forever. Re-running the driver against a
  job a human is already reviewing must not open a second row, and must not
  reset the age that row is sorted by.

  changed evidence under an open case is a revision. An overwrite alone would
  leave a case whose rows are no longer the rows the analyst read, with nothing
  on the record to say so.

  a job id never becomes a path. The id is derived, so a hand-edited finding
  cannot write outside the store.

  an unreadable case is still listed. Dropping it would remove a case from the
  queue silently, which is the one failure mode a governance console cannot
  have.

run:  python3 -m pytest tests/test_cases.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from caseharden import cases  # noqa: E402

JOB = "europe-west3:job_5UcJoBBEaZWU0"


def finding(**over) -> dict:
    base = {"job_id": JOB, "family": "injected_turn",
            "window_start": "2026-08-27T09:00:00Z",
            "window_end": "2026-08-30T09:00:00Z",
            "sessions_total": 27,
            "rows": [{"session_id": "s_1", "turns": "2"}]}
    base.update(over)
    return base


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

def test_the_same_job_republished_is_the_same_case(tmp_path):
    first = cases.open_case(tmp_path, finding(), now="2026-08-30T10:00:00Z")
    second = cases.open_case(tmp_path, finding(), now="2026-08-30T12:00:00Z")
    assert first["case_id"] == second["case_id"]
    assert len(list(tmp_path.glob("*.json"))) == 1
    # The age a queue sorts on is the age of the case, not of the last write.
    assert second["opened_at"] == "2026-08-30T10:00:00Z"
    assert second["revisions"] == 0, "identical content is not a revision"


def test_changed_evidence_is_a_revision_of_the_open_case(tmp_path):
    cases.open_case(tmp_path, finding(), now="2026-08-30T10:00:00Z")
    moved = cases.open_case(tmp_path, finding(sessions_total=31),
                            now="2026-08-30T12:00:00Z")
    assert moved["opened_at"] == "2026-08-30T10:00:00Z"
    assert moved["revised_at"] == "2026-08-30T12:00:00Z"
    assert moved["revisions"] == 1
    assert len(list(tmp_path.glob("*.json"))) == 1
    # Counted, not flagged. One revision proves nothing about the arithmetic: a
    # counter pinned at 1 passed a test that only ever revised once.
    again = cases.open_case(tmp_path, finding(sessions_total=44),
                            now="2026-08-30T13:00:00Z")
    assert again["revisions"] == 2
    assert again["revised_at"] == "2026-08-30T13:00:00Z"
    assert again["opened_at"] == "2026-08-30T10:00:00Z"


def test_a_new_run_over_the_same_evidence_is_not_a_revision(tmp_path):
    """The driver stamps every finding with a fresh run envelope.

    `context_id` is a uuid4 per run and both window bounds come from the clock,
    so hashing the whole finding made `revisions` count republications: a case
    whose conduct rows had not moved was reported as changed evidence.
    """
    first = finding(context_id="loop-investigation-aaaa",
                    window_start="2026-08-27T09:00:00Z",
                    window_end="2026-08-30T09:00:00Z",
                    report="the Foreman said one thing")
    second = finding(context_id="loop-investigation-bbbb",
                     window_start="2026-08-27T11:00:00Z",
                     window_end="2026-08-30T11:00:00Z",
                     report="the Foreman said it differently")
    assert cases.content_hash(first) == cases.content_hash(second)
    cases.open_case(tmp_path, first, now="2026-08-30T10:00:00Z")
    again = cases.open_case(tmp_path, second, now="2026-08-30T12:00:00Z")
    assert again["revisions"] == 0
    assert again["revised_at"] is None


def test_a_field_the_hash_did_not_cover_is_named_on_the_record(tmp_path):
    case = cases.open_case(tmp_path, finding(context_id="x", report="y"))
    assert "context_id" not in case["hashed_keys"]
    assert "report" not in case["hashed_keys"]
    assert {"job_id", "family", "rows", "sessions_total"} <= set(case["hashed_keys"])


def test_a_field_nobody_classified_still_counts_as_evidence(tmp_path):
    """A finding gains a field; the safe default is that it changes the hash."""
    plain = finding()
    assert cases.content_hash(plain) != cases.content_hash(
        dict(plain, some_future_detector_field="a"))


def test_two_jobs_are_two_cases(tmp_path):
    cases.open_case(tmp_path, finding())
    cases.open_case(tmp_path, finding(job_id="europe-west3:job_other"))
    assert len(list(tmp_path.glob("*.json"))) == 2
    assert cases.list_cases(tmp_path)["total"] == 2


def test_key_order_alone_is_not_a_change(tmp_path):
    """The driver builds the finding as a literal, and literals get reordered."""
    plain = finding()
    reordered = {k: plain[k] for k in reversed(list(plain))}
    assert cases.content_hash(plain) == cases.content_hash(reordered)


def test_a_finding_with_no_job_id_is_refused(tmp_path):
    for bad in ({}, {"job_id": ""}, {"job_id": None}, {"job_id": ["a"]}):
        try:
            cases.open_case(tmp_path, dict(bad))
        except ValueError:
            continue
        raise AssertionError(f"{bad} opened a case")


# --------------------------------------------------------------------------
# A job id never becomes a path
# --------------------------------------------------------------------------

def test_a_hostile_job_id_stays_inside_the_store(tmp_path):
    store = tmp_path / "cases"
    outside = tmp_path / "escaped.json"
    case = cases.open_case(store, finding(job_id="../escaped"))
    assert cases.CASE_ID_RE.match(case["case_id"])
    assert not outside.exists()
    assert [p.name for p in store.glob("*.json")] == [f"{case['case_id']}.json"]
    # The id is derived, and the id it derived from is still on the record.
    assert case["job_id"] == "../escaped"


def test_read_case_refuses_an_id_it_did_not_produce(tmp_path):
    cases.open_case(tmp_path, finding())
    # Right length, wrong alphabet, and right alphabet, wrong length: the regex
    # has to hold both ends or a path fragment gets through on one of them.
    # The trailing newline is in the list because `$` matches before one.
    for bad in ("../../etc/passwd", "..", "", "g" * 16, "0123456789abcdeff",
                "0123456789abcdef\n"):
        assert cases.read_case(tmp_path, bad) is None
        assert not cases.CASE_ID_RE.match(bad), bad


def test_a_readable_case_file_outside_the_store_is_never_served(tmp_path):
    """The property, not one of the two checks that hold it.

    A valid case file is planted where a relative id would reach it. The id
    shape refuses the id, and the name-derives-from-the-job-id check refuses the
    file: no string can satisfy both a path that leaves the directory and a
    16-character hex digest. This fails if either the shape check or the
    identity check is the only one left, so it is worth more than a test that
    only names a file which does not exist.
    """
    store = tmp_path / "cases"
    cases.open_case(store, finding())
    planted = tmp_path / "planted.json"
    planted.write_text(json.dumps(
        {"case_id": cases.case_id(JOB), "job_id": JOB, "finding": finding()}))
    for reach in ("../planted", "..%2Fplanted", "../../planted"):
        assert cases.read_case(store, reach) is None
    assert planted.exists(), "the store must not have written over it either"


# --------------------------------------------------------------------------
# Listing
# --------------------------------------------------------------------------

def test_an_unreadable_case_is_listed_first_and_not_dropped(tmp_path):
    good = cases.open_case(tmp_path, finding(), now="2026-08-30T10:00:00Z")
    (tmp_path / ("f" * 16 + ".json")).write_text('{"case_id": "fff", "job')
    listed = cases.list_cases(tmp_path)
    assert listed["total"] == 2
    assert listed["unreadable"] == 1
    assert "error" in listed["cases"][0], "the broken case is not at the top"
    assert listed["cases"][1]["case_id"] == good["case_id"]


def test_the_newest_case_is_first(tmp_path):
    old = cases.open_case(tmp_path, finding(), now="2026-08-28T10:00:00Z")
    new = cases.open_case(tmp_path, finding(job_id="europe-west3:job_new"),
                          now="2026-08-30T10:00:00Z")
    order = [c["case_id"] for c in cases.list_cases(tmp_path)["cases"]]
    assert order == [new["case_id"], old["case_id"]]


def test_a_store_that_does_not_exist_yet_lists_empty(tmp_path):
    listed = cases.list_cases(tmp_path / "nothing")
    assert listed["cases"] == [] and listed["total"] == 0
    assert listed["truncated"] is False


def test_a_page_that_ends_at_its_limit_says_so(tmp_path):
    """A silently short page reads as the whole store.

    Which cases survive the limit is decided by file mtime and the page is then
    sorted by `opened_at`, so the case that falls off is not the one at the
    bottom of what is shown.
    """
    for n in range(4):
        cases.open_case(tmp_path, finding(job_id=f"europe-west3:job_{n}"))
    listed = cases.list_cases(tmp_path, limit=2)
    assert len(listed["cases"]) == 2
    assert listed["total"] == 4
    assert listed["truncated"] is True
    assert listed["limit"] == 2
    assert cases.list_cases(tmp_path, limit=4)["truncated"] is False


def test_the_summary_carries_no_decision(tmp_path):
    """A disposition here would be a second copy of a `review.decisions` row."""
    case = cases.open_case(tmp_path, finding())
    row = cases.summarise(case)
    assert set(row) & {"decision", "disposition", "approved", "analyst"} == set()
    assert row["sessions_total"] == 27 and row["rows_shown"] == 1


def test_a_case_holds_the_evidence_the_summary_leaves_out(tmp_path):
    cid = cases.open_case(tmp_path, finding())["case_id"]
    stored = cases.read_case(tmp_path, cid)
    assert stored["finding"]["rows"] == [{"session_id": "s_1", "turns": "2"}]
    assert json.loads((tmp_path / f"{cid}.json").read_text())["job_id"] == JOB


def test_a_corrupt_case_does_not_block_the_next_publish(tmp_path):
    """Refusing to publish over a file somebody corrupted loses the finding."""
    cid = cases.case_id(JOB)
    (tmp_path / f"{cid}.json").write_text("{ not json")
    case = cases.open_case(tmp_path, finding(), now="2026-08-30T10:00:00Z")
    assert case["opened_at"] == "2026-08-30T10:00:00Z"
    assert case["revisions"] == 0
    assert cases.read_case(tmp_path, cid)["job_id"] == JOB


# --------------------------------------------------------------------------
# A file this module did not write
# --------------------------------------------------------------------------

def _write(tmp_path, cid, case) -> Path:
    path = tmp_path / f"{cid}.json"
    path.write_text(json.dumps(case))
    return path


def test_a_case_whose_name_does_not_derive_from_its_job_id_is_refused(tmp_path):
    """The edit that binds one case's evidence to another finding's verdict.

    `/api/cases?id=` looks the decision up by the stored `job_id` and shows the
    stored `finding`. Editing one and not the other puts job A's rows beside the
    review row filed against job B, and the id is a function of the job id, so
    the mismatch is detectable without a second record.
    """
    cid = cases.case_id(JOB)
    _write(tmp_path, cid, {"case_id": cid, "job_id": "europe-west3:job_other",
                           "finding": finding()})
    assert cases.read_case(tmp_path, cid) is None
    assert cases.list_cases(tmp_path)["unreadable"] == 1


def test_a_case_id_field_that_disagrees_with_the_filename_is_refused(tmp_path):
    cid = cases.case_id(JOB)
    _write(tmp_path, cid, {"case_id": "0" * 16, "job_id": JOB, "finding": finding()})
    assert cases.read_case(tmp_path, cid) is None


def test_a_symlink_in_the_store_is_not_served(tmp_path):
    """A link inside the store points wherever it was made to point.

    The target is a case that is valid in every other way: right filename, right
    `case_id`, a `job_id` that derives to it. That is what makes this a test of
    the symlink check rather than of the identity check, which refuses a
    mismatched file wherever it sits. The bytes a governance console reads have
    to come from the directory it was pointed at.
    """
    cid = cases.case_id(JOB)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps(
        {"case_id": cid, "job_id": JOB, "opened_at": "2026-08-30T10:00:00Z",
         "finding": finding()}))
    store = tmp_path / "cases"
    store.mkdir()
    (store / f"{cid}.json").symlink_to(elsewhere)
    assert cases.read_case(store, cid) is None
    assert cases.list_cases(store)["unreadable"] == 1


def test_a_case_with_an_unusable_revision_count_is_replaced_not_raised(tmp_path):
    """`int("bad")` reached the driver, which reported the whole store as broken."""
    cid = cases.case_id(JOB)
    _write(tmp_path, cid, {"case_id": cid, "job_id": JOB, "revisions": "bad",
                           "opened_at": {"not": "a stamp"}, "finding": finding()})
    case = cases.open_case(tmp_path, finding(sessions_total=31),
                           now="2026-08-30T10:00:00Z")
    assert case["revisions"] == 1
    assert case["opened_at"] == "2026-08-30T10:00:00Z"


def test_surrounding_whitespace_is_not_a_second_case(tmp_path):
    """A stored job id that no `review.decisions` row can match is a dead case."""
    assert cases.case_id(JOB) == cases.case_id(f"  {JOB} ")
    case = cases.open_case(tmp_path, finding(job_id=f" {JOB}\n"))
    assert case["job_id"] == JOB
    assert cases.read_case(tmp_path, case["case_id"])["job_id"] == JOB
