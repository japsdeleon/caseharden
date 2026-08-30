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

import pytest
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

    `context_id` correlates one investigation's agent calls and `report` is the
    Foreman's prose. Both change on every run, so hashing them made `revisions`
    count republications: a case whose conduct rows had not moved was reported
    as changed evidence.
    """
    first = finding(context_id="loop-investigation-aaaa",
                    report="the Foreman said one thing")
    second = finding(context_id="loop-investigation-bbbb",
                     report="the Foreman said it differently")
    assert cases.content_hash(first) == cases.content_hash(second)
    cases.open_case(tmp_path, first, now="2026-08-30T10:00:00Z")
    again = cases.open_case(tmp_path, second, now="2026-08-30T12:00:00Z")
    assert again["revisions"] == 0
    assert again["revised_at"] is None


def test_a_changed_evidence_window_is_a_revision(tmp_path):
    """The window looks clock-derived and is provenance.

    `investigate()` computes it from the time of the run, which is what made an
    earlier version of this store treat it as envelope. It is the window the
    detectors scanned, and it travels into the promotion bundle as exactly that,
    so a case that kept its first window while the finding carried another would
    be read as evidence gathered over a period it was not.
    """
    cases.open_case(tmp_path, finding(window_end="2026-08-30T09:00:00Z"),
                    now="2026-08-30T10:00:00Z")
    moved = cases.open_case(tmp_path, finding(window_end="2026-08-30T11:00:00Z"),
                            now="2026-08-30T12:00:00Z")
    assert moved["revisions"] == 1
    assert moved["opened_at"] == "2026-08-30T10:00:00Z"


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

    The target is a case this module wrote and would otherwise accept, so the
    only thing refusing it is the link. Hand-building the target instead left it
    failing the evidence check, and the test then passed with the symlink guard
    deleted. The bytes a governance console reads have to come from the
    directory it was pointed at.
    """
    other = tmp_path / "other"
    cid = cases.open_case(other, finding())["case_id"]
    elsewhere = other / f"{cid}.json"
    assert cases.read_case(other, cid) is not None, "the target must be a valid case"
    store = tmp_path / "cases"
    store.mkdir()
    (store / f"{cid}.json").symlink_to(elsewhere)
    assert cases.read_case(store, cid) is None
    assert cases.list_cases(store)["unreadable"] == 1


def test_a_case_with_an_unusable_revision_count_is_replaced_not_raised(tmp_path):
    """`int("bad")` reached the driver, which reported the whole store as broken.

    The case is edited after `open_case` wrote it, and only in fields the
    content hash does not cover, so it stays a readable case and the bad values
    genuinely reach the code that carries them forward. Writing the whole file
    by hand would fail the evidence check instead and never get that far.
    """
    cid = cases.open_case(tmp_path, finding(), now="2026-08-29T10:00:00Z")["case_id"]
    path = tmp_path / f"{cid}.json"
    stored = json.loads(path.read_text())
    stored["revisions"] = "bad"
    stored["opened_at"] = {"not": "a stamp"}
    path.write_text(json.dumps(stored))
    assert cases.read_case(tmp_path, cid) is not None, "the edit broke the hash"

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


# --------------------------------------------------------------------------
# The stored hash describes the stored finding
# --------------------------------------------------------------------------

def _tamper(tmp_path, mutate) -> str:
    """Open a real case, then edit its stored finding in place."""
    cid = cases.open_case(tmp_path, finding(), now="2026-08-30T10:00:00Z")["case_id"]
    path = tmp_path / f"{cid}.json"
    stored = json.loads(path.read_text())
    mutate(stored)
    path.write_text(json.dumps(stored))
    return cid


def test_edited_evidence_under_an_untouched_wrapper_is_refused(tmp_path):
    """The wrapper was the only thing checked, and it is not where evidence is."""
    cid = _tamper(tmp_path, lambda c: c["finding"].update(
        rows=[{"session_id": "s_forged", "turns": "99"}]))
    assert cases.read_case(tmp_path, cid) is None
    assert cases.list_cases(tmp_path)["unreadable"] == 1


def test_tampered_evidence_does_not_survive_a_republish(tmp_path):
    """The edit outlived republication, which is what made it worth fixing.

    `open_case` compares the incoming finding against the stored digest. The
    digest was never checked against the stored finding, so a genuine republish
    of the real finding matched it, returned early, and handed back the edited
    case without rewriting it.
    """
    cid = _tamper(tmp_path, lambda c: c["finding"].update(rows=[{"session_id": "s_forged"}]))
    reopened = cases.open_case(tmp_path, finding(), now="2026-08-30T12:00:00Z")
    assert reopened["case_id"] == cid
    assert reopened["finding"]["rows"] == [{"session_id": "s_1", "turns": "2"}]
    assert cases.read_case(tmp_path, cid)["finding"]["rows"] == [
        {"session_id": "s_1", "turns": "2"}]


def test_a_finding_naming_another_job_than_its_wrapper_is_refused(tmp_path):
    cid = _tamper(tmp_path, lambda c: c["finding"].update(
        job_id="europe-west3:job_somewhere_else"))
    assert cases.read_case(tmp_path, cid) is None


def test_a_hash_recorded_under_an_older_key_list_still_checks(tmp_path):
    """A case carries the keys its hash covered, so the list can change later.

    Without this, changing RUN_ENVELOPE would make every case already on disk
    unreadable, and a queue full of cases marked corrupt is indistinguishable
    from a store somebody attacked.
    """
    cid = cases.case_id(JOB)
    body = finding()
    keys = sorted(k for k in body if k != "sessions_total")
    _write(tmp_path, cid, {
        "case_id": cid, "job_id": JOB, "opened_at": "2026-08-30T10:00:00Z",
        "content_hash": cases.content_hash(body, keys), "hashed_keys": keys,
        "revisions": 0, "finding": body})
    assert cases.read_case(tmp_path, cid) is not None
    # And the field that list left out is still not a way in: the recorded list
    # is what gets recomputed, so removing a key from it changes the digest.
    _write(tmp_path, cid, {
        "case_id": cid, "job_id": JOB, "opened_at": "2026-08-30T10:00:00Z",
        "content_hash": cases.content_hash(body, keys), "hashed_keys": keys[:2],
        "revisions": 0, "finding": body})
    assert cases.read_case(tmp_path, cid) is None


def test_a_deleted_field_cannot_pass_by_disappearing(tmp_path):
    cid = _tamper(tmp_path, lambda c: c["finding"].pop("rows"))
    assert cases.read_case(tmp_path, cid) is None


def test_a_store_that_is_a_symlink_is_refused_on_both_sides(tmp_path):
    """mkdir(exist_ok=True) and replace both follow a linked directory."""
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "cases"
    linked.symlink_to(real)
    with pytest.raises(OSError):
        cases.open_case(linked, finding())
    assert list(real.iterdir()) == []
    assert cases.read_case(linked, cases.case_id(JOB)) is None
    assert "symbolic link" in cases.list_cases(linked)["error"]


def test_a_case_read_through_a_linked_store_is_refused(tmp_path):
    """The file exists and is valid; the directory it was reached through is not.

    Distinct from the write side: `open_case` refusing means nothing was ever
    written, so a read that returns None proves only that the file is absent.
    Here the case is genuinely there, behind the link.
    """
    real = tmp_path / "real"
    cid = cases.open_case(real, finding())["case_id"]
    assert cases.read_case(real, cid) is not None, "the case must be readable directly"
    linked = tmp_path / "cases"
    linked.symlink_to(real)
    assert cases.read_case(linked, cid) is None


def test_a_forged_key_list_cannot_hide_a_swapped_job_id(tmp_path):
    """The last thing standing when the hash itself has been recomputed.

    An editor who drops `job_id` from `hashed_keys` and recomputes the digest
    over what is left passes the hash check. The finding then names one job
    while the wrapper names another, and the console would look the verdict up
    by the wrapper and show the other job's rows.
    """
    cid = cases.case_id(JOB)
    body = finding(job_id="europe-west3:job_somewhere_else")
    keys = sorted(k for k in body if k != "job_id")
    _write(tmp_path, cid, {
        "case_id": cid, "job_id": JOB, "opened_at": "2026-08-30T10:00:00Z",
        "content_hash": cases.content_hash(body, keys), "hashed_keys": keys,
        "revisions": 0, "finding": body})
    assert cases.read_case(tmp_path, cid) is None
