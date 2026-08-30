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
CASE_ID_RE = re.compile(r"^[0-9a-f]{16}$")


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


def content_hash(finding: dict) -> str:
    """A hash of the finding as published, stable against key order.

    `sort_keys` because the driver builds this dict literal-first and a future
    edit that reorders it must not read as changed evidence. `default=str`
    because the rows come back from BigQuery carrying dates.
    """
    body = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
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
    """Every case in the store, unreadable ones first.

    Unreadable first, rather than sorted to the bottom by a missing timestamp: a
    case whose file will not parse is the one an operator has to be told about,
    and the bottom of a long queue is where it would never be seen.
    """
    if not cases_dir.is_dir():
        return {"dir": str(cases_dir), "cases": [], "total": 0, "unreadable": 0}

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
            "total": len(paths), "unreadable": len(broken)}
