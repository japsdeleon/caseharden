#!/usr/bin/env python3
"""Re-check an exported chain with no cloud access, on a clean checkout.

`caseharden verify` is the product, and it needs this project's BigQuery, the
sealed holdout, and two impersonated service accounts. Nobody outside the
project can run it. That makes every green line in this repo a claim about a
machine one person owns, which is a weak position for an entry whose subject is
records you can check for yourself.

So this exists. Given the fixture in `fixtures/<version>/` it re-checks, with a
Python interpreter and nothing else:

  1  every link's hash, recomputed from its own fields
  2  the walk: each link names the previous link's hash
  3  the root, against the hash sealed in the retention-locked bucket
  4  the certificate's own list of per-link hashes
  5  the shape: a promotion begins with EVIDENCE and carries an EXAM and an APPROVAL
  6  the approval names the exam it approved
  7  the EVIDENCE link's digests against the material listed in that same link
  8  the EXAM link's measurements, REPLAYED from the committed seeded generator

Only 8 is a re-derivation from data. The generator is seeded and committed, so
it reproduces the corpora BigQuery was loaded from, and the Examiner is
deterministic and makes no model calls. If the recorded catch rate was invented,
this disagrees.

Checks 1 to 7 are internal consistency. They prove the record was not edited
after it was sealed. They cannot prove the record was true when it was written;
that is what the live `verify` does, against the warehouse.

usage:
  python3 -m caseharden.recheck fixtures/v5
  python3 -m caseharden.recheck fixtures/v5 --skip-replay   (hash checks only)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import chain
from .dsl import parse
from .interpreter import structurally_monotonic

REQUIRED_KINDS = ("EXAM", "APPROVAL")


class Result:
    """Every check, with the reason it passed or failed. Nothing is silent.

    `quiet` suppresses only the printing. A caller that renders the checks
    somewhere other than a terminal still gets every one of them in `checks`,
    because a check that is not reported is the same as a check that did not run.
    """

    def __init__(self, quiet: bool = False) -> None:
        self.checks: List[tuple] = []
        self.quiet = quiet

    def add(self, ok: bool, title: str, detail: str = "") -> bool:
        self.checks.append((ok, title, detail))
        if not self.quiet:
            print(f"  {'ok  ' if ok else 'FAIL'}  {title}" + (f"  {detail}" if detail else ""))
        return ok

    @property
    def failed(self) -> List[tuple]:
        return [c for c in self.checks if not c[0]]


def load_links(path: Path) -> List[chain.Link]:
    links = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        links.append(chain.Link(row["version"], int(row["seq"]), row["kind"],
                                row["payload"], row["prev_hash"], row["link_hash"],
                                row.get("written_at")))
    return sorted(links, key=lambda l: l.seq)


def check_hashes(links, result: Result) -> None:
    broken = [l.seq for l in links if not l.intact()]
    result.add(not broken, f"all {len(links)} link hashes recompute from their own fields",
               f"broken at {broken}" if broken else "")

    walk_ok, detail = True, ""
    for index, link in enumerate(links):
        expected = links[index - 1].hash if index else ""
        if (link.prev_hash or "") != expected:
            walk_ok = False
            detail = f"link {link.seq} names {link.prev_hash[:12]!r}, not {expected[:12]!r}"
            break
    result.add(walk_ok, "the chain walks: every link names the one before it", detail)

    seqs = [l.seq for l in links]
    result.add(seqs == list(range(1, len(links) + 1)),
               "sequence numbers are 1..N with no gaps", str(seqs) if seqs != list(
                   range(1, len(links) + 1)) else "")


def check_certificate(links, certificate: dict, result: Result) -> None:
    root = chain.root_of(links)
    sealed = certificate.get("root")
    result.add(root == sealed,
               "the chain root matches the root in the exported sealed certificate",
               f"chain {(root or '')[:16]} vs sealed {(sealed or '')[:16]}"
               if root != sealed else (root or "")[:16])

    listed = {int(entry["seq"]): entry["hash"] for entry in certificate.get("links", [])}
    mismatched = [l.seq for l in links if listed.get(l.seq) not in (None, l.hash)]
    missing = [l.seq for l in links if l.seq not in listed]
    result.add(not mismatched and not missing,
               f"the certificate lists the same {len(listed)} link hashes",
               f"mismatched {mismatched} missing {missing}" if (mismatched or missing) else "")


def check_shape(links, result: Result) -> None:
    kinds = [l.kind for l in links]
    result.add(bool(kinds) and kinds[0] == "EVIDENCE",
               "a promotion begins with EVIDENCE",
               f"link 1 is {kinds[0]}" if kinds and kinds[0] != "EVIDENCE" else "")
    for required in REQUIRED_KINDS:
        result.add(required in kinds, f"the chain carries a {required} link")

    approval = next((l for l in links if l.kind == "APPROVAL"), None)
    exam_hashes = {l.hash for l in links if l.kind == "EXAM"}
    named = (approval.payload.get("approves_exam_hash") if approval else None)
    result.add(bool(named) and named in exam_hashes,
               "the approval names the exam it approved",
               (named or "none")[:16])


def check_evidence(links, result: Result) -> None:
    """The EVIDENCE link against the material listed inside it.

    Internal consistency, and it is labelled as such. A payload whose digest
    disagrees with its own event list has been edited by something that did not
    understand what it was editing.
    """
    evidence = [l for l in links if l.kind in ("EVIDENCE", "EVIDENCE-CHANGED")]
    if not evidence:
        result.add(False, "the chain carries an EVIDENCE link")
        return
    for link in evidence:
        p = link.payload
        events = p.get("events")
        if events is None:
            result.add(True, f"link {link.seq} carries a digest without an event list",
                       f"{p.get('row_count')} events, above the payload cap")
        else:
            result.add(chain.digest_rows(events) == p.get("event_digest"),
                       f"link {link.seq} event digest matches its own {len(events)} events")
            result.add(len(events) == p.get("row_count"),
                       f"link {link.seq} row count matches the event list",
                       f"{p.get('row_count')} recorded")
        for field, pairs in (("access_digest", p.get("access")),
                             ("exam_reach_digest", p.get("exam_reach"))):
            if pairs is None:
                continue
            digest = hashlib.sha256("\n".join(pairs).encode()).hexdigest()
            result.add(digest == p.get(field),
                       f"link {link.seq} {field} matches its own {len(pairs)} entries")


def check_exam(links, result: Result) -> None:
    """Replay the Examiner over the regenerated corpora and compare.

    This is the only check here that derives anything. The generator is seeded
    and committed, so it reproduces the corpora that were loaded into BigQuery,
    and the Examiner is deterministic with no model calls. A recorded catch rate
    that never happened does not survive this.
    """
    from .examiner import local_corpora, score_local

    exam_link = None
    for link in links:
        if link.kind == "EXAM":
            exam_link = link
        if link.kind == "EVIDENCE-CHANGED" and "exam" in link.payload:
            exam_link = link
    if exam_link is None:
        result.add(False, "the chain carries an EXAM link")
        return
    exam = exam_link.payload.get("exam", exam_link.payload)

    candidate, current = parse(exam["candidate"]), parse(exam["current"])
    corpora = local_corpora()
    measured = score_local(candidate, corpora)

    families = sorted(k for k in exam["holdout"] if k != "benign")
    disagreed = []
    for family in families:
        stored = exam["holdout"][family]
        local = measured.holdout.get(family, {})
        if (int(stored.get("denied_sessions", -1)) != int(local.get("denied_sessions", -2))
                or int(stored.get("sessions", -1)) != int(local.get("sessions", -2))):
            disagreed.append(
                f"{family}: recorded {stored.get('denied_sessions')}/{stored.get('sessions')}, "
                f"replay {local.get('denied_sessions')}/{local.get('sessions')}")
    caught = sum(int(exam["holdout"][f].get("denied_sessions", 0)) for f in families)
    total = sum(int(exam["holdout"][f].get("sessions", 0)) for f in families)
    result.add(not disagreed,
               f"the Examiner's sealed-attack numbers replay: {caught}/{total} sessions",
               "; ".join(disagreed))

    stored_benign = exam["benign"]["benign"]
    local_benign = measured.benign.get("benign", {})
    same = (int(stored_benign.get("denied_turns", -1)) == int(local_benign.get("denied_turns", -2))
            and int(stored_benign.get("turns", -1)) == int(local_benign.get("turns", -2)))
    result.add(same,
               f"the benign numbers replay: "
               f"{int(stored_benign.get('turns', 0)) - int(stored_benign.get('denied_turns', 0))}"
               f"/{stored_benign.get('turns')} turns pass",
               "" if same else f"replay says {local_benign.get('denied_turns')} denied")

    monotone, uncovered = structurally_monotonic(candidate, current)
    result.add(monotone, "the promoted candidate denies everything its parent denied",
               f"uncovered: {uncovered}" if uncovered else "")

    result.add(str(exam.get("verdict", "")).upper().startswith("PROMOTION ALLOWED")
               or "GATE PASS" in str(exam.get("verdict", "")).upper(),
               "the recorded gate verdict is a pass", str(exam.get("verdict", ""))[:60])


def run_checks(directory: Path, skip_replay: bool = False,
               quiet: bool = False) -> Result:
    """Every offline check over one fixture directory, as data.

    Separate from `recheck` so a caller that is not a terminal gets the checks
    themselves rather than an exit code and some stdout.
    """
    result = Result(quiet=quiet)
    links = load_links(directory / "chain.jsonl")
    certificate = json.loads((directory / "certificate.json").read_text())

    check_hashes(links, result)
    check_certificate(links, certificate, result)
    check_shape(links, result)
    check_evidence(links, result)
    if not skip_replay:
        check_exam(links, result)
    return result


def recheck(directory: Path, skip_replay: bool = False) -> int:
    links = load_links(directory / "chain.jsonl")

    print(f"caseharden recheck {directory}")
    print(f"  {len(links)} links, version {links[0].version if links else '?'}, "
          f"no cloud access used")
    print()

    result = run_checks(directory, skip_replay)
    if skip_replay:
        print("  ....  the Examiner replay was skipped by request")

    print()
    if result.failed:
        print(f"  {len(result.failed)} CHECK(S) FAILED")
        for _, title, detail in result.failed:
            print(f"    - {title}" + (f": {detail}" if detail else ""))
        return 1
    print(f"  ALL {len(result.checks)} CHECKS HELD.")
    print("  Hashes and the seal prove the record was not edited. The Examiner replay")
    print("  proves its measurements were not invented. Whether the record was true when")
    print("  it was written is what the live `caseharden verify` re-derives, against the")
    print("  warehouse, and it cannot be answered from a fixture.")
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Re-check an exported chain offline.")
    parser.add_argument("directory", help="a fixture directory, for example fixtures/v5")
    parser.add_argument("--skip-replay", action="store_true",
                        help="hash and shape checks only; do not regenerate the corpora")
    args = parser.parse_args(argv)
    return recheck(Path(args.directory), args.skip_replay)


if __name__ == "__main__":
    raise SystemExit(main())
