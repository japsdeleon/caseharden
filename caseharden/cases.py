#!/usr/bin/env python3
"""The case store: findings, addressable one at a time.

Why this exists. `infra/110_run_loop.py` published its finding to a single file,
`out/finding-live.json`, and the next run replaced it. That is enough for a
console that shows the one case a person is being asked about right now, and it
is why `docs/WORKBENCH_SPRINT.md` refused to build a queue: a queue enumerates
cases, and there was exactly one, with no name of its own and no age that
outlived the file.

This module gives a finding three things it did not have:

  a stable id, so the same detector job is the same case on every republish and
  a link to it survives the next run,

  a content hash, so evidence that changes underneath an open case shows up as
  a revision instead of a silent overwrite,

  an open timestamp that survives republication, so "how long has a human been
  sitting on this" is a fact about the case rather than the file's mtime.

What it deliberately does not hold: the decision. A verdict lives in
`review.decisions`, written by the Copilot under `analyst-sa`. A copy of it here
would be a second record of the same decision, free to disagree with the first,
and nothing would say which one governed. Callers that need a disposition look
it up per case from the warehouse.

Where that property actually lives, because it is not enforced here. This
module adds no disposition field and its summary emits none, but `open_case`
writes the finding it is given verbatim, so a caller that put a verdict inside a
finding would see it on disk. The one caller is `publish_finding`, and it runs
at `infra/110_run_loop.py` before the verdict is requested, which is what keeps
a decision out of these files. A second caller would have to keep that order.

This store is an index over findings, not the record of them. The record is the
detector's BigQuery job, which is re-runnable, and the chain. So a failure to
write a case is a degraded queue and never a failed run.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import List, Optional

CASES_DIRNAME = "cases"

# A directory read on a route the browser reaches. Local, and the loop writes
# one case per run, so this is a ceiling rather than a defence: it keeps a
# console that has been left running for a week from parsing every finding ever
# published on each poll. The count of what was left out travels with the list.
MAX_CASES_LISTED = 200

# What `case_id` produces, and the only thing `read_case` will open. The id is
# derived, so anything that fails this did not come from here.
#
# `\Z` and not `$`: `$` also matches before a trailing newline, so
# `0123456789abcdef\n` passed a check whose whole job is to say the string came
# from `case_id`. It could not have reached a path outside the store, having no
# slash in it, but the route answered 404 where it had promised 400.
CASE_ID_RE = re.compile(r"^[0-9a-f]{16}\Z")

# Which parts of a finding are not evidence. Each of these changes on every run
# whether or not anything was found: `context_id` is a fresh uuid4 per run,
# `report` is the Foreman's prose, and both window bounds come from the clock at
# `investigate()`. Hashing them made `revisions` count republications, so a case
# whose rows were byte-identical was reported as revised evidence.
#
# An exclusion list rather than a list of evidence fields, so a field added to
# the finding later counts by default. An extra revision is noise on a screen; a
# missed one is evidence swapped under a case with nothing saying so.
RUN_ENVELOPE = frozenset({"context_id", "report", "window_start", "window_end"})


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_id(job_id: str) -> str:
    """The stable name of the case that reviews this detector job.

    Derived from the job id rather than being it. A BigQuery job id arrives as
    `europe-west3:job_nwzQ...`, and this name becomes a filename and a query
    parameter: taking the id verbatim would put a caller's string in a path, and
    a hand-edited finding carrying `../../` would then write outside the store.
    A hex digest cannot leave the directory it is joined to.

    Sixteen hex characters, because the collision that matters is between the
    handful of detector jobs a fleet opens, not between arbitrary inputs.

    Hashed after `strip`, and the stripped form is what `open_case` records.
    Surrounding whitespace made `job_x ` a second case with the same evidence,
    and its stored job id would then have matched no `review.decisions` row: the
    driver and the console both compare `subject` for equality.
    """
    if not isinstance(job_id, str) or not job_id.strip():
        raise ValueError("a finding with no job id has nothing to be a case about")
    return hashlib.sha256(job_id.strip().encode("utf-8")).hexdigest()[:16]


def hashed_keys(finding: dict) -> List[str]:
    """The finding's fields that `content_hash` covers, for the record.

    Written into the case so a reader can see what the hash was taken over
    rather than inferring it from this module's source at some later version.
    """
    return sorted(k for k in finding if k not in RUN_ENVELOPE)


def content_hash(finding: dict) -> str:
    """A hash of the evidence in a finding, stable against key order.

    Evidence, not the whole finding: see `RUN_ENVELOPE` for what is left out and
    why. This answers one question, "are these the same rows the analyst was
    looking at", and the run envelope makes every publication look different.

    `sort_keys` because the driver builds this dict literal-first and a future
    edit that reorders it must not read as changed evidence. `default=str` is a
    guard, not a conversion the known path needs: `bq._decode` returns only what
    the REST encoding carries, which is strings, lists, dicts and None. It is
    here because `open_case` hashes whatever a caller passes, and an
    unserialisable value would otherwise raise out of a hash.
    """
    body = json.dumps({k: finding[k] for k in hashed_keys(finding)},
                      sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def atomic_write_json(target: Path, payload) -> None:
    """Write whole, then move into place, under a name no other writer shares.

    The workbench polls these files while the driver writes them, and a partial
    read costs an analyst a blank pane at the exact moment they are being
    recorded.

    The scratch name is unique per call. A fixed one was shared by every run:
    two drivers alive at once, which is what a re-run after a failed take looks
    like, wrote the same scratch file and the second `replace` died with
    FileNotFoundError because the first had already moved it away. An
    adversarial pass reproduced that 100 times out of 100 paired runs.

    Pid alone was not enough, and the same reproduction said so: it separates
    two processes and not two threads. The random suffix is what makes the name
    unique, and `replace` is atomic, so the loser of a race is overwritten
    rather than crashed.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    scratch = target.parent / f"{target.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.part"
    try:
        scratch.write_text(json.dumps(payload, indent=2, default=str) + "\n")
        scratch.replace(target)
    finally:
        # A failed write leaves a uniquely named file behind, and every retry
        # leaves another. After a successful replace there is nothing here to
        # remove, which is why this is missing_ok.
        scratch.unlink(missing_ok=True)


def open_case(cases_dir: Path, finding: dict, now: Optional[str] = None) -> dict:
    """Record this finding as a case, or update the case it already is.

    Republishing the same detector job keeps the case: same id, same
    `opened_at`. Only the hash decides whether anything happened. Identical
    content is not rewritten at all, so a driver restarted against the same job
    does not reset the age a queue sorts on.

    Changed content under an open case is a revision, not a new case. The pair
    of counters is the whole point of hashing here: a case a human has been
    reading for two hours whose evidence was replaced ten minutes ago is a fact
    the console has to be able to show, and an overwrite alone erases it.

    An unreadable existing case is treated as no case, and so is one carrying a
    field this function cannot use. The alternative is refusing to publish
    because of a file somebody corrupted, which loses the finding to protect the
    index. `revisions: "bad"` in a file that is otherwise valid JSON raised out
    of `int()` and reached the driver, which reported the store as unwritable
    when the store was fine and one file was not.

    Two publishers of the same job id at the same time is a read-then-write
    race this does not close: both read no case, both write, and the later one
    keeps its own `opened_at` and leaves `revisions` a count short. The driver
    allocates a fresh detector job per run, so two publishers of one job id
    means the same job published twice deliberately, and the cost when it
    happens is a timestamp off by the gap between the two writes. A lock across
    processes would buy a correct counter and a component that can wedge; the
    counter is not worth that.
    """
    stamp = now or _now()
    cid = case_id(finding.get("job_id"))
    target = cases_dir / f"{cid}.json"

    previous = read_case(cases_dir, cid)
    digest = content_hash(finding)
    if previous and previous.get("content_hash") == digest:
        return previous

    case = {
        "case_id": cid,
        "job_id": finding["job_id"].strip(),
        "family": finding.get("family"),
        "opened_at": _stamp_or(previous, "opened_at", stamp),
        "content_hash": digest,
        "hashed_keys": hashed_keys(finding),
        "revisions": _count(previous) + (1 if previous else 0),
        "revised_at": stamp if previous else None,
        "finding": finding,
    }
    atomic_write_json(target, case)
    return case


def _stamp_or(previous: Optional[dict], field: str, fallback: str) -> str:
    """A timestamp carried forward from the existing case, if it is one.

    A non-string in `opened_at` would be carried into the queue and sorted
    against real timestamps, which is how one hand-edited file reorders every
    row around it.
    """
    value = (previous or {}).get(field)
    return value if isinstance(value, str) and value else fallback


def _count(previous: Optional[dict]) -> int:
    value = (previous or {}).get("revisions")
    return value if isinstance(value, int) and value >= 0 else 0


def read_case(cases_dir: Path, cid: str) -> Optional[dict]:
    """One case by id, or None when there is no readable case under that name.

    The id is checked against the shape this module produces before it is joined
    to a path. The HTTP layer checks it too; this is the check that holds for
    every other caller, including the driver.

    A corrupt file reads as absent here. `list_cases` is where an unreadable
    case is reported, because a queue that quietly drops a case is the one
    failure a governance console cannot have.

    Two more things make a file unreadable, and neither is a parse error:

      a symlink under this directory. The id is checked, so the path is inside
      the store, but a link inside it points wherever it was made to point and
      the console would serve that file's contents to a browser. The analyst
      could read those files anyway; the console reading them on a query
      parameter is a different thing, and refusing costs one call.

      a case whose name does not derive from its own job id. The id is a
      function of `job_id`, so a file that fails to round-trip was written by
      something other than `open_case`. An edited one binds this case's
      evidence to another finding's verdict: the pane would show job A's rows
      beside the review row filed against job B.
    """
    # Redundant for this function's result, and kept anyway. Removing it changes
    # no answer, because no string can both leave the directory and derive from
    # a job id, so the round-trip check below refuses whatever the shape check
    # would have. It stays because it is what stops a caller-supplied string
    # reaching a path join at all, and a later edit to the round-trip check
    # should not be the only thing between the two. A mutation deleting this
    # line survives the suite; that is the redundancy, not a gap.
    if not isinstance(cid, str) or not CASE_ID_RE.match(cid):
        return None
    path = cases_dir / f"{cid}.json"
    if path.is_symlink():
        return None
    try:
        case = json.loads(path.read_text())
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(case, dict):
        return None
    try:
        derived = case_id(case.get("job_id"))
    except ValueError:
        return None
    if derived != cid or case.get("case_id") != cid:
        return None
    return case


def summarise(case: dict) -> dict:
    """The row a queue draws, without the evidence behind it.

    Everything here is a fact the store wrote. Nothing is computed from the
    reader's clock or inferred from the file: age is the caller's subtraction
    from `opened_at`, and severity is not this module's to invent.
    """
    finding = case.get("finding") or {}
    rows = finding.get("rows")
    return {
        "case_id": case.get("case_id"),
        "job_id": case.get("job_id"),
        "family": case.get("family"),
        "opened_at": case.get("opened_at"),
        "revised_at": case.get("revised_at"),
        "revisions": case.get("revisions", 0),
        "content_hash": case.get("content_hash"),
        "window_start": finding.get("window_start"),
        "window_end": finding.get("window_end"),
        "sessions_total": finding.get("sessions_total"),
        "rows_shown": len(rows) if isinstance(rows, list) else None,
    }


def list_cases(cases_dir: Path, limit: int = MAX_CASES_LISTED) -> dict:
    """The most recently written cases in the store, unreadable ones first.

    Unreadable first, rather than sorted to the bottom by a missing timestamp: a
    case whose file will not parse is the one an operator has to be told about,
    and the bottom of a long queue is where it would never be seen.

    Two orders, and they are not the same one. Which cases survive the limit is
    decided by when their file was last written; what is returned is then sorted
    by when each case was opened. So an old case nobody has touched is the first
    to fall off, which is the opposite of what a queue sorted on age is for.
    `truncated` says when that has happened and `total` says by how much,
    because a page that silently ends at its limit reads as the whole store.
    Above the limit, the fix is a stored index rather than a different sort:
    ordering by `opened_at` first would mean parsing every file to choose 200.
    """
    if not cases_dir.is_dir():
        return {"dir": str(cases_dir), "cases": [], "total": 0, "unreadable": 0,
                "limit": limit, "truncated": False}

    paths = sorted(cases_dir.glob("*.json"),
                   key=lambda p: p.stat().st_mtime if p.exists() else 0,
                   reverse=True)
    broken: List[dict] = []
    rows: List[dict] = []
    for path in paths[:max(0, limit)]:
        case = read_case(cases_dir, path.stem)
        if case is None:
            broken.append({"case_id": path.stem, "error": "unreadable case file",
                           "path": str(path)})
        else:
            rows.append(summarise(case))
    rows.sort(key=lambda r: r.get("opened_at") or "", reverse=True)
    return {"dir": str(cases_dir), "cases": broken + rows,
            "total": len(paths), "unreadable": len(broken),
            "limit": limit, "truncated": len(paths) > max(0, limit)}
