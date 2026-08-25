#!/usr/bin/env python3
"""The Notary: writes the chain, seals the root, and re-derives it on demand.

`verify` is the product. It walks the hash chain, then re-runs the two links
that are derivations: the conduct events the finding cited, together with the
access list of the sealed exam, and the Examiner's measurements over that exam.
A version is served as attested only while all of that reproduces.

Three states, and the important one is what quarantine does not do:

  attested      everything re-derives and the root matches its sealed certificate
  quarantined   a leg fails. The version KEEPS ENFORCING. What it loses is its
                standing as justified, and the fleet's ability to promote on top
                of it
  unknown       verification itself could not run. Enforcement unchanged, last
                known state retained, promotion frozen

Attestation gates authority, not availability. An audit layer that switches off
guardrails when it gets confused is a worse failure than the one it detects.

usage:
  python -m caseharden.notary verify   --version v4
  python -m caseharden.notary reattest --version v4
  python -m caseharden.notary promote  --version v5 --candidate C --parent v4
  python -m caseharden.notary seed     --version v4 --candidate policies/v4-candidate-b.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from . import bq, chain
from .chain import ChainStore, Evidence, Link
from .dsl import Policy, canonical_json, load, parse
from .examiner import Score, gate
from .interpreter import structurally_monotonic

REPO = Path(__file__).resolve().parent.parent

ATTESTED = "attested"
QUARANTINED = "quarantined"
UNKNOWN = "unknown"

# Named on screen when a version is quarantined, so the break is a place in the
# record rather than an adjective.
LINK_HASH = "LINK-HASH"            # the chain itself was edited
EVENT_WINDOW = "EVENT-WINDOW"      # the cited conduct events are no longer those events
HOLDOUT_ACCESS = "HOLDOUT-ACCESS"  # who may read the exam has changed
EXAM_SCORE = "EXAM-SCORE"          # the Examiner no longer measures what was promoted on
ROOT_MISMATCH = "ROOT-MISMATCH"    # the chain and its sealed certificate disagree
NO_CHAIN = "NO-CHAIN"              # nothing was ever written for this version
NO_CERTIFICATE = "NO-CERTIFICATE"  # the chain has no sealed root to be checked against
CHAIN_SHAPE = "CHAIN-SHAPE"        # the links are not a promotion

# A break that says the record was edited is not repaired by re-deriving over
# the edit. reattest refuses these two and says so.
NOT_REATTESTABLE = (LINK_HASH, ROOT_MISMATCH, NO_CHAIN, NO_CERTIFICATE, CHAIN_SHAPE)


class LinkResult:
    def __init__(self, seq: int, kind: str, status: str, mode: str, detail: str):
        self.seq = seq
        self.kind = kind
        self.status = status      # OK | BREAK | SUPERSEDED | SKIPPED
        self.mode = mode          # re-derived | recorded
        self.detail = detail

    def as_dict(self) -> dict:
        return {"seq": self.seq, "kind": self.kind, "status": self.status,
                "mode": self.mode, "detail": self.detail}


class Attestation:
    def __init__(self, version: str, state: str, results: Sequence[LinkResult],
                 root: Optional[str], break_code: Optional[str] = None,
                 break_seq: Optional[int] = None, break_detail: str = "",
                 elapsed_s: float = 0.0, break_event: Optional[str] = None):
        self.version = version
        self.state = state
        self.results = list(results)
        self.root = root
        self.break_code = break_code
        self.break_seq = break_seq
        self.break_detail = break_detail
        self.elapsed_s = elapsed_s
        self.break_event = break_event

    @property
    def attested(self) -> bool:
        return self.state == ATTESTED

    @property
    def promotions(self) -> str:
        return "OPEN" if self.attested else "FROZEN"

    def as_dict(self) -> dict:
        out = {
            "version": self.version,
            "attested": self.attested,
            "state": self.state.upper(),
            "promotions": self.promotions,
            "root": self.root,
            "verify_seconds": round(self.elapsed_s, 3),
            "links": [r.as_dict() for r in self.results],
        }
        if self.break_code:
            out["break"] = f"link {self.break_seq} {self.break_code}"
            out["break_detail"] = self.break_detail
            if self.break_event:
                out["event"] = self.break_event
        return out


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

def _walk_hashes(links: Sequence[Link]) -> Optional[Tuple[int, str]]:
    """First structural break in the chain, or None.

    Checked before any re-derivation. Re-deriving against a payload that has
    already been shown to be edited would answer a question about the edit.
    """
    prev = None
    for link in links:
        if link.prev_hash != (prev or ""):
            return link.seq, (f"link {link.seq} points at {link.prev_hash[:12] or '<none>'}, "
                              f"but link {link.seq - 1} hashes to {(prev or '<none>')[:12]}")
        if not link.intact():
            return link.seq, (f"the payload no longer hashes to {link.hash[:12]}; "
                              f"it now hashes to {link.recomputed()[:12]}")
        prev = link.hash
    return None


def _describe_events(payload: dict, actual: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    """Compare the cited events, and their contents, with the warehouse now.

    Returns the description and, separately, the first offending event id. The
    id is carried as its own field so a caller can act on it without parsing
    prose, which is also the shape the demo's 2:52 response is written in.
    """
    if chain.digest_rows(actual) == payload["event_digest"]:
        return None, None
    stored = payload.get("events")
    if stored is None:
        return (f"{len(actual)} events now in the cited window, {payload['row_count']} when "
                f"the version was promoted; the link carries a digest only, so no id is named"), None
    added = sorted(set(actual) - set(stored))
    removed = sorted(set(stored) - set(actual))
    altered = sorted(k for k in set(actual) & set(stored) if actual[k] != stored[k])
    parts = []
    if added:
        parts.append(f"{len(added)} event(s) in the window are not in the cited set: "
                     + _some(added))
    if removed:
        parts.append(f"{len(removed)} cited event(s) are gone: " + _some(removed))
    if altered:
        parts.append(f"{len(altered)} cited event(s) no longer match the row that was "
                     f"cited: " + _some(altered))
    return "; ".join(parts), (added + altered + removed)[0]


def _some(ids: Sequence[str], limit: int = 5) -> str:
    return ", ".join(ids[:limit]) + (" ..." if len(ids) > limit else "")


def _required_shape(links: Sequence[Link]) -> Optional[Tuple[int, str]]:
    """Is this sequence of links a promotion at all?

    A hash chain proves its links are consecutive, not that they say anything.
    An adversarial pass wrote a single fabricated FINDING link, sealed its root,
    and verification called it ATTESTED: nothing had required the chain to carry
    the evidence, the exam, or the approval it claims to attest to. So the
    grammar is checked rather than assumed.
    """
    if [l.seq for l in links] != list(range(1, len(links) + 1)):
        return links[-1].seq, "the sequence numbers are not 1..N with no gaps"
    kinds = [l.kind for l in links]
    if kinds[0] != "EVIDENCE":
        return 1, f"link 1 is {kinds[0]}, and a promotion begins with EVIDENCE"
    for required in ("EXAM", "APPROVAL"):
        if required not in kinds:
            return links[-1].seq, f"the chain carries no {required} link"
    return None


def _describe_access(payload: dict, entries: Sequence[dict]) -> Optional[str]:
    if chain.digest_access(entries) == payload["access_digest"]:
        return None
    now = set(chain._access_pairs(entries))
    then = set(payload.get("access", []))
    parts = []
    if now - then:
        parts.append("granted since promotion: " + ", ".join(sorted(now - then)))
    if then - now:
        parts.append("revoked since promotion: " + ", ".join(sorted(then - now)))
    return "; ".join(parts) or "the exam's access list no longer hashes to the sealed value"


def _describe_reach(payload: dict, evidence: Evidence) -> Optional[str]:
    """Compare who could reach the sealed exam through project-level IAM.

    The dataset access list is one of two ways to reach a table. A project-level
    binding is the other, and it never shows up in the ACL, so hashing the ACL
    alone left the easier grant unnoticed.
    """
    bindings = evidence.exam_reach()
    if chain.digest_reach(bindings) == payload["exam_reach_digest"]:
        return None
    now = set(chain._reach_pairs(bindings))
    then = set(payload.get("exam_reach", []))
    parts = []
    if now - then:
        parts.append("project-level roles granted since promotion: "
                     + ", ".join(sorted(now - then)))
    if then - now:
        parts.append("project-level roles revoked since promotion: "
                     + ", ".join(sorted(then - now)))
    return "; ".join(parts) or "project-level access to the exam no longer hashes to the sealed value"


def _score_delta(stored: dict, measured: Score) -> Optional[str]:
    """Compare the exam link's measurements against a fresh run of the Examiner.

    The candidate's side only, and that is sufficient rather than lazy. A gate
    that passed means the candidate is structurally monotone over the active
    version, which means it denies everything the active version denies. So the
    two scores cannot move independently: the per-label `turns` and `sessions`
    totals are the same scan for both, and no row can leave the active version's
    denial set without leaving the candidate's. Re-scoring the active version
    would add a BigQuery scan to every verify and detect nothing.

    Keys absent from the stored payload are skipped, so a chain written before a
    measurement was added still verifies.
    """
    for name, now in (("holdout", measured.holdout), ("benign", measured.benign)):
        was = stored.get(name)
        if was is None:
            continue
        if was != now:
            changed = sorted(set(was) | set(now))
            for label in changed:
                if was.get(label) != now.get(label):
                    return (f"{name}/{label}: the Examiner measured {was.get(label)} "
                            f"at promotion and measures {now.get(label)} now")
    return None


def verify(version: str, links: Sequence[Link], evidence: Evidence,
           sealed: Optional[dict] = None) -> Attestation:
    """Re-derive a version's chain. Never raises for a data problem; it reports one."""
    started = time.monotonic()

    def done(state, results, code=None, seq=None, detail="", event=None):
        return Attestation(version, state, results, chain.root_of(links), code, seq,
                           detail, time.monotonic() - started, event)

    if not links:
        return done(QUARANTINED, [], NO_CHAIN, 0, f"no chain has been written for {version}")

    structural = _walk_hashes(links)
    if structural:
        seq, detail = structural
        # Nothing is re-derived on this path, so no link is reported as having
        # been. The links before the break passed the hash check and no more.
        results = [
            LinkResult(l.seq, l.kind,
                       "OK" if l.seq < seq else ("BREAK" if l.seq == seq else "SKIPPED"),
                       "recorded",
                       detail if l.seq == seq else
                       ("hash intact; re-derivation not reached" if l.seq < seq else ""))
            for l in links
        ]
        return done(QUARANTINED, results, LINK_HASH, seq, detail)

    shape = _required_shape(links)
    if shape:
        seq, detail = shape
        return done(QUARANTINED,
                    [LinkResult(l.seq, l.kind, "SKIPPED", "recorded", "") for l in links],
                    CHAIN_SHAPE, seq, detail)

    evidence_links = [l for l in links if l.kind in ("EVIDENCE", "EVIDENCE-CHANGED")]
    effective_evidence = evidence_links[-1] if evidence_links else None
    exam_source = None
    for l in links:
        if l.kind == "EXAM":
            exam_source = (l.seq, l.payload)
    if effective_evidence is not None and "exam" in effective_evidence.payload:
        exam_source = (effective_evidence.seq, effective_evidence.payload["exam"])

    results: List[LinkResult] = []
    break_code = break_seq = break_event = None
    break_detail = ""

    def note(link: Link, status: str, mode: str, detail: str) -> None:
        results.append(LinkResult(link.seq, link.kind, status, mode, detail))

    try:
        for link in links:
            payload = link.payload
            try:
                _shape_of_payload(link)
            except (KeyError, ValueError) as exc:
                # A payload that does not parse is a malformed record, not an
                # outage, so it quarantines rather than raising. Reaching this
                # needs write access to the chain table, since editing a payload
                # in place breaks the hash walk above.
                detail = f"link {link.seq} {link.kind} payload is malformed: {exc}"
                note(link, "BREAK", "re-derived", detail)
                results.extend(LinkResult(l.seq, l.kind, "SKIPPED", "recorded", "")
                               for l in links if l.seq != link.seq
                               and l.seq not in {r.seq for r in results})
                return done(QUARANTINED, results, CHAIN_SHAPE, link.seq, detail)
            if link.kind in ("EVIDENCE", "EVIDENCE-CHANGED"):
                if link is not effective_evidence:
                    note(link, "SUPERSEDED", "recorded",
                         f"restated by link {effective_evidence.seq}")
                    continue
                actual = evidence.cited_events(
                    payload["dataset"], payload["window_start"], payload["window_end"])
                problem, offender = _describe_events(payload, actual)
                if problem:
                    note(link, "BREAK", "re-derived", problem)
                    break_code, break_seq, break_detail = EVENT_WINDOW, link.seq, problem
                    break_event = offender
                    break
                entries = evidence.access_list(payload["exam_dataset"])
                problem = _describe_access(payload, entries)
                if problem:
                    note(link, "BREAK", "re-derived", problem)
                    break_code, break_seq, break_detail = HOLDOUT_ACCESS, link.seq, problem
                    break
                problem = _describe_reach(payload, evidence)
                if problem:
                    note(link, "BREAK", "re-derived", problem)
                    break_code, break_seq, break_detail = HOLDOUT_ACCESS, link.seq, problem
                    break
                detail = (f"{len(actual)} conduct events re-scanned over "
                          f"{payload['window_start']}..{payload['window_end']}, "
                          f"{payload['exam_dataset']} readable by {len(entries)} principal(s)")
                # An EVIDENCE-CHANGED link restates the exam as well as the
                # evidence. Re-deriving only its evidence half left the exam
                # unchecked for the rest of the version's life, from the first
                # re-attestation onward. That is the demo's own remedy beat
                # switching off the entry's central claim.
                if link.seq == (exam_source or (None,))[0]:
                    measured, problem = _redo_exam(payload["exam"], evidence)
                    if problem:
                        note(link, "BREAK", "re-derived", problem)
                        break_code, break_seq, break_detail = EXAM_SCORE, link.seq, problem
                        break
                    detail += f"; {_exam_detail(measured)}"
                note(link, "OK", "re-derived", detail)
            elif link.kind == "EXAM" and exam_source and exam_source[0] == link.seq:
                measured, problem = _redo_exam(payload, evidence)
                if problem:
                    note(link, "BREAK", "re-derived", problem)
                    break_code, break_seq, break_detail = EXAM_SCORE, link.seq, problem
                    break
                note(link, "OK", "re-derived", _exam_detail(measured))
            elif link.kind == "EXAM":
                note(link, "SUPERSEDED", "recorded",
                     f"re-scored under link {exam_source[0]}" if exam_source else "")
            elif link.kind == "APPROVAL":
                problem = _describe_approval(payload, links)
                if problem:
                    note(link, "BREAK", "recorded", problem)
                    break_code, break_seq, break_detail = CHAIN_SHAPE, link.seq, problem
                    break
                note(link, "OK", "recorded", _recorded_detail(link))
            else:
                note(link, "OK", "recorded", _recorded_detail(link))
    except (bq.BigQueryError, bq.IncompleteResult, RuntimeError) as exc:
        results.append(LinkResult(0, "VERIFY", "BREAK", "re-derived", str(exc)))
        return done(UNKNOWN, results, None, None, str(exc))

    if break_code:
        seen = {r.seq for r in results}
        results.extend(LinkResult(l.seq, l.kind, "SKIPPED", "recorded", "")
                       for l in links if l.seq not in seen)
        return done(QUARANTINED, results, break_code, break_seq, break_detail, break_event)

    root = chain.root_of(links)
    if sealed is None:
        return done(QUARANTINED, results, NO_CERTIFICATE, links[-1].seq,
                    "no sealed certificate is registered for this version, so the chain "
                    "has nothing to be checked against; truncating it would go unnoticed")
    if sealed.get("root") != root:
        detail = (f"the chain roots to {root[:12]} and the sealed certificate "
                  f"carries {str(sealed.get('root'))[:12]}")
        return done(QUARANTINED, results, ROOT_MISMATCH, links[-1].seq, detail)

    return done(ATTESTED, results, None)


def _shape_of_payload(link: Link) -> None:
    """Raise if this link's payload is not what its kind has to carry.

    Checked per link rather than once up front, so the break names the link that
    is malformed instead of the chain as a whole.
    """
    p = link.payload
    # What each recorded kind must at least carry. Verification re-derives the
    # evidence and the exam and nothing else, so for these kinds the check is
    # that the link says something rather than that what it says is true. An
    # adversarial pass sealed a chain whose HOLDOUT-DENIED link was an empty
    # object and verification called it attested.
    required = {
        "FINDING": ("family", "job_id"),
        "DRAFT-REJECTED": ("error",),
        "HOLDOUT-DENIED": ("principal", "dataset", "permission", "http_code"),
    }.get(link.kind)
    if required:
        for key in required:
            if key not in p or p[key] in (None, "", {}, []):
                raise KeyError(key)
        if link.kind == "HOLDOUT-DENIED" and str(p["http_code"]) != "403":
            raise ValueError(
                f"a HOLDOUT-DENIED link records a refusal; this one records "
                f"HTTP {p['http_code']}")
    if link.kind in ("EVIDENCE", "EVIDENCE-CHANGED"):
        for key in ("dataset", "window_start", "window_end", "event_digest",
                    "exam_dataset", "access_digest", "exam_reach_digest", "row_count"):
            if key not in p:
                raise KeyError(key)
    exam = p.get("exam") if link.kind == "EVIDENCE-CHANGED" else (
        p if link.kind == "EXAM" else None)
    if exam is not None:
        for key in ("candidate", "current", "holdout", "benign"):
            if key not in exam:
                raise KeyError(key)
        parse(exam["candidate"])
        parse(exam["current"])


def _redo_exam(exam: dict, evidence: Evidence) -> Tuple[Optional[Score], Optional[str]]:
    """Run the Examiner again over the sealed holdout and compare."""
    measured = evidence.score(parse(exam["candidate"]))
    return measured, _score_delta(exam, measured)


def _exam_detail(measured: Score) -> str:
    return (f"the Examiner re-scores {measured.attacks_caught}/"
            f"{measured.attacks_total} sealed attack sessions at "
            f"{measured.benign_pass_rate:.0%} benign pass, unchanged")


def _describe_approval(payload: dict, links: Sequence[Link]) -> Optional[str]:
    """The approval has to name the exam it approved.

    The field was written and read nowhere, which made the binding between an
    approval and the measurements it approved a note rather than a check.
    """
    named = payload.get("approves_exam_hash")
    if not named:
        return "the approval does not name the exam it approved"
    if named not in {l.hash for l in links if l.kind == "EXAM"}:
        return f"the approval names exam {named[:12]}, which is not a link in this chain"
    return None


def _recorded_detail(link: Link) -> str:
    p = link.payload
    if link.kind == "FINDING":
        total = p.get("sessions_total", len(p.get("sessions", [])))
        job = p.get("job_id") or ""
        return (f"{p.get('family')}, {total} session(s)"
                + (f", job {job.split(':')[-1][:20]}" if job else ""))
    if link.kind == "VERDICT":
        return f"{p.get('disposition')} by {p.get('analyst')}"
    if link.kind == "DRAFT":
        return f"candidate {p.get('version')}, {p.get('rule_count')} rule(s)"
    if link.kind == "DRAFT-REJECTED":
        return str(p.get("error", ""))[:70]
    if link.kind == "HOLDOUT-DENIED":
        return f"{p.get('principal')} refused {p.get('permission')} on {p.get('dataset')}"
    if link.kind == "APPROVAL":
        return f"{p.get('verdict')} approved by {p.get('approver')}"
    return ""


# --------------------------------------------------------------------------
# reattest
# --------------------------------------------------------------------------

def reattest(version: str, links: Sequence[Link], evidence: Evidence,
             sealed: Optional[dict] = None) -> Tuple[Attestation, Optional[Link], str]:
    """Re-derive against the evidence as it now stands, and record the change.

    Returns the attestation it started from, the link to append if the gate still
    passes, and the sentence to print. Appending and re-sealing are the caller's
    to do, so this function is pure and the test suite can run it offline.

    The fix is re-derivation, not editing the record. The superseded EVIDENCE
    link stays exactly where it was.
    """
    before = verify(version, links, evidence, sealed)
    if before.attested:
        return before, None, f"{version} is attested. Nothing to re-derive."
    if before.state == UNKNOWN:
        return before, None, "REFUSED. Verification could not run, so there is nothing to re-derive against."
    if before.break_code in NOT_REATTESTABLE:
        return before, None, (
            f"REFUSED. The break is {before.break_code}: the record itself was altered. "
            f"Re-attestation re-derives over evidence, it does not launder an edit.")
    if before.break_code == HOLDOUT_ACCESS and "granted since promotion" in before.break_detail:
        return before, None, (
            "REFUSED. The exam's access list was widened. Re-attesting would record the "
            "new reader as the justified state, which is the isolation guarantee this "
            "link exists to protect. Revoke the grant, then re-attest.")

    evidence_links = [l for l in links if l.kind in ("EVIDENCE", "EVIDENCE-CHANGED")]
    prior = evidence_links[-1].payload
    exam = prior.get("exam") or next(
        l.payload for l in links if l.kind == "EXAM")

    candidate, current = parse(exam["candidate"]), parse(exam["current"])
    cand_score = evidence.score(candidate)
    curr_score = evidence.score(current)
    monotone, uncovered = structurally_monotonic(candidate, current)
    verdict = gate(cand_score, curr_score, monotone, uncovered,
                   evidence.widened(candidate, current))

    if not verdict.passed:
        return before, None, (
            f"REFUSED. Re-scored against current evidence the gate no longer passes: "
            f"{verdict.reason}. {version} stays quarantined and keeps enforcing.")

    events = evidence.cited_events(
        prior["dataset"], prior["window_start"], prior["window_end"])
    entries = evidence.access_list(prior["exam_dataset"])
    payload = _evidence_payload(
        prior["dataset"], prior["window_start"], prior["window_end"], events,
        prior["exam_dataset"], entries, evidence.exam_reach())
    payload["supersedes"] = evidence_links[-1].seq
    payload["reason"] = f"{before.break_code}: {before.break_detail}"
    payload["exam"] = _exam_payload(candidate, current, cand_score, curr_score, verdict)

    seq = links[-1].seq + 1
    link = Link(version, seq, "EVIDENCE-CHANGED", payload, links[-1].hash)
    return before, link, (
        f"RE-ATTESTED. The evidence moved, the gate still passes "
        f"({cand_score.attacks_caught}/{cand_score.attacks_total} sealed attacks at "
        f"{cand_score.benign_pass_rate:.0%} benign pass). Link {seq} EVIDENCE-CHANGED records "
        f"the new evidence and supersedes link {payload['supersedes']}.")


# --------------------------------------------------------------------------
# Payload builders, shared by seed and reattest
# --------------------------------------------------------------------------

def bind_approval(links: List[Link]) -> List[Link]:
    """Point the APPROVAL link at the hash of the exam it approved.

    The hash is only knowable once the exam link exists, so the approval is
    built with the field empty and the tail of the chain is rehashed here. That
    binding is what `verify` checks: without it, an approval is a signature on
    nothing in particular.
    """
    exam = next((l for l in links if l.kind == "EXAM"), None)
    index = next((i for i, l in enumerate(links) if l.kind == "APPROVAL"), None)
    if exam is None or index is None:
        return links
    out = list(links[:index])
    prev = out[-1].hash if out else None
    for link in links[index:]:
        payload = (dict(link.payload, approves_exam_hash=exam.hash)
                   if link.kind == "APPROVAL" else link.payload)
        out.append(Link(link.version, link.seq, link.kind, payload, prev))
        prev = out[-1].hash
    return out


def _evidence_payload(dataset: str, start: str, end: str, events: Dict[str, str],
                      exam_dataset: str, access: Sequence[dict],
                      reach: Sequence[dict]) -> dict:
    payload = {
        "dataset": dataset,
        "window_start": start,
        "window_end": end,
        "row_count": len(events),
        "event_digest": chain.digest_rows(events),
        "exam_dataset": exam_dataset,
        "access_digest": chain.digest_access(access),
        "access": chain._access_pairs(access),
        "exam_reach_digest": chain.digest_reach(reach),
        "exam_reach": chain._reach_pairs(reach),
    }
    if len(events) <= chain.MAX_CITED_EVENTS:
        payload["events"] = dict(sorted(events.items()))
    return payload


def _exam_payload(candidate: Policy, current: Policy, cand: Score, curr: Score,
                  verdict) -> dict:
    return {
        "candidate": json.loads(canonical_json(candidate)),
        "current": json.loads(canonical_json(current)),
        "holdout": cand.holdout,
        "benign": cand.benign,
        "current_holdout": curr.holdout,
        "current_benign": curr.benign,
        "verdict": verdict.reason,
        "checks": [[name, ok, detail] for name, ok, detail in verdict.checks],
    }


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

MARK = {"OK": "OK  ", "BREAK": "BREAK", "SUPERSEDED": "----", "SKIPPED": "    "}


def print_attestation(att: Attestation) -> None:
    print(f"caseharden verify conduct-policy@{att.version}")
    print()
    for r in att.results:
        mark = MARK.get(r.status, r.status)
        print(f"  [{r.seq}] {r.kind:<17}{mark:<7}{r.detail}")
    print()
    if att.root:
        print(f"  root {att.root}")
    if att.attested:
        print(f"  ATTESTED   re-derived from raw events in {att.elapsed_s:.1f}s")
    elif att.state == UNKNOWN:
        print(f"  UNKNOWN    verification could not run: {att.break_detail}")
        print(f"             enforcement unchanged, last known state retained, "
              f"promotions {att.promotions}")
    else:
        print(f"  QUARANTINED  break at link {att.break_seq} {att.break_code}")
        print(f"               {att.break_detail}")
        print(f"               enforcement unchanged, promotions {att.promotions}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _tokens(project: str, args) -> Tuple[str, Evidence, ChainStore]:
    """Two identities, because the exam has exactly one reader.

    The Notary re-scans the conduct events and reads the exam's access list. The
    exam's rows are re-scored under examiner-sa, and the Notary holds no grant
    that would let it do that itself.
    """
    notary = args.impersonate or f"notary-sa@{project}.iam.gserviceaccount.com"
    args.notary_sa = notary
    examiner = f"examiner-sa@{project}.iam.gserviceaccount.com"
    notary_token = bq.access_token(notary)
    examiner_token = bq.access_token(examiner)
    evidence = chain.BigQueryEvidence(project, notary_token, examiner_token)
    return notary_token, evidence, ChainStore(project, notary_token)


def _sealed_for(store: ChainStore, version: str, impersonate: Optional[str] = None
                ) -> Optional[dict]:
    rows = [r for r in store.versions() if r["version"] == version]
    if not rows or not rows[0].get("certificate_uri"):
        return None
    return chain.sealed_root(rows[0]["certificate_uri"], impersonate)


def cmd_verify(args) -> int:
    _, evidence, store = _tokens(args.project, args)
    links = store.read(args.version)
    att = verify(args.version, links, evidence, _sealed_for(store, args.version, args.notary_sa))
    if args.json:
        print(json.dumps(att.as_dict(), indent=2))
    else:
        print_attestation(att)
    return 0 if att.attested else (7 if att.state == UNKNOWN else 6)


def cmd_reattest(args) -> int:
    _, evidence, store = _tokens(args.project, args)
    links = store.read(args.version)
    before, link, message = reattest(args.version, links, evidence,
                                     _sealed_for(store, args.version, args.notary_sa))
    print_attestation(before)
    print()
    print(message)
    if link is None:
        return 0 if before.attested else 6
    store.append(link)
    links = store.read(args.version)
    uri = chain.seal(args.bucket, args.version, link.seq, chain.root_of(links), links,
                     args.notary_sa)
    rows = [r for r in store.versions() if r["version"] == args.version]
    if rows:
        # repoint, not register: register marks its version active and every
        # other one inactive, so re-attesting an old version would put that
        # version back in force. Re-derivation changes what a version can claim.
        # It must never change what the fleet enforces.
        store.repoint(args.version, chain.root_of(links), uri)
    else:
        # A chain with no registry row was never promoted, so there is nothing to
        # re-point at the new root. Say so rather than writing a half row that the
        # Policy Server would later fail to parse.
        print(f"note: {args.version} has no row in policy.versions; "
              f"the new root was sealed but not registered")
    print(f"sealed {uri}")
    print()
    after = verify(args.version, links, evidence, chain.sealed_root(uri, args.notary_sa))
    print_attestation(after)
    return 0 if after.attested else 6


def parent_basis(store, evidence: Evidence, parent: str,
                 notary_sa: Optional[str]) -> Tuple[Optional[str], Optional[Attestation]]:
    """May a new version be built on `parent`? Returns the basis, or None.

    Called from `seed` as well as `promote`. `promote` on its own was a
    pre-check that wrote nothing and that nothing forced anyone to run, which
    made the freeze advisory: `seed` would write a chain onto a quarantined
    parent, or onto a version name that had never existed, and mark it active.
    """
    links = store.read(parent)
    if links:
        attestation = verify(parent, links, evidence, _sealed_for(store, parent, notary_sa))
        if not attestation.attested:
            return None, attestation
        return f"{parent} attested at root {attestation.root[:12]}", attestation
    rows = [r for r in store.versions() if r["version"] == parent]
    if rows and not rows[0].get("root"):
        return f"{parent} is the registered genesis version and carries no chain", None
    return None, None


def _refuse_parent(version: str, parent: str, attestation: Optional[Attestation]) -> int:
    if attestation is not None:
        print_attestation(attestation)
        print()
        print(f"REFUSED — cannot build on an unattested version. "
              f"{parent} is {attestation.state.upper()} "
              f"(break at link {attestation.break_seq} {attestation.break_code}).")
    else:
        print(f"REFUSED — {parent} is not a version of this policy. It has no chain and "
              f"no registry row, so there is nothing to build on. Register the first "
              f"version with `notary genesis` if this is it.")
    print(f"{version} was not promoted and nothing was written to the chain.")
    return 5


def cmd_promote(args) -> int:
    """A promotion is refused on an unattested parent. That is the freeze."""
    _, evidence, store = _tokens(args.project, args)
    candidate = load(args.candidate)
    basis, attestation = parent_basis(store, evidence, args.parent, args.notary_sa)
    if basis is None:
        return _refuse_parent(args.version, args.parent, attestation)
    digest = hashlib.sha256(canonical_json(candidate).encode()).hexdigest()
    print(f"parent accepted: {basis}")
    print(f"candidate {args.candidate}: {len(candidate.rules)} deny rule(s), "
          f"digest {digest[:12]}")
    print(f"{args.version} may be promoted. Run seed to write its chain.")
    return 0


def cmd_genesis(args) -> int:
    """Register the first version, the one that carries no chain.

    Without a registered genesis, `seed` cannot tell a legitimate first
    promotion from a chain built on a version name nobody ever promoted.
    """
    _, _, store = _tokens(args.project, args)
    policy = load(args.policy)
    if store.read(args.version):
        print(f"{args.version} has a chain; it is not a genesis version.")
        return 2
    store.register(args.version, None, canonical_json(policy), "", "")
    print(f"registered {args.version} as the genesis version, active, with no chain")
    return 0


def cmd_certificate(args) -> int:
    from .certificate import render
    _, evidence, store = _tokens(args.project, args)
    links = store.read(args.version)
    att = verify(args.version, links, evidence,
                 _sealed_for(store, args.version, args.notary_sa))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(att, links))
    print(f"wrote {out}")
    return 0


def cmd_seed(args) -> int:
    """Write one promotion's chain, from artifacts the fleet produced or this made.

    Two ways in. Without `--bundle` the Notary produces the finding itself, by
    running its own SQL over the training window, and the human inputs are
    command-line flags. That is what Day 3 meant by hand-fed links, and it still
    works, because a chain has to be writable before the agents that fill it
    exist.

    With `--bundle` the links come from the run that actually happened: the
    FINDING is a detector's answer with that detector's BigQuery job id, the
    VERDICT is the row a human wrote through the Analyst Copilot with the Model
    Armor result on their words, the DRAFT is what the Proposer emitted, any
    draft the grammar refused is its own link, and HOLDOUT-DENIED is the refusal
    the Proposer itself received when it tried to score against the exam.

    Either way the numbers are measured here rather than copied in: the cited
    events are re-scanned from BigQuery and the exam is the Examiner's own
    output, run now, under examiner-sa.
    """
    notary_token, evidence, store = _tokens(args.project, args)
    candidate, current = load(args.candidate), load(args.current)
    bundle = json.loads(Path(args.bundle).read_text()) if args.bundle else {}
    for field in ("dataset", "window_start", "window_end", "approver"):
        if bundle.get(field):
            setattr(args, field.replace("-", "_"), bundle[field])

    if store.read(args.version):
        print(f"{args.version} already has a chain. Delete it or pick another version.")
        return 2

    # The freeze is enforced here, at the point that actually writes a chain and
    # marks a version active, not only in the separate `promote` pre-check.
    basis, attestation = parent_basis(store, evidence, args.parent, args.notary_sa)
    if basis is None:
        return _refuse_parent(args.version, args.parent, attestation)
    print(f"parent accepted: {basis}")

    events = evidence.cited_events(args.dataset, args.window_start, args.window_end)
    access = evidence.access_list("holdout_sealed")
    evidence_payload = _evidence_payload(args.dataset, args.window_start, args.window_end,
                                         events, "holdout_sealed", access,
                                         evidence.exam_reach())

    if bundle.get("finding"):
        # The detector's own answer, with the job id it ran and the trace ids of
        # the conduct rows it cited. Day 4 shipped a FINDING the Notary wrote
        # itself over a different table from the one the fleet scans, so the two
        # never met; this is where they do.
        finding = bundle["finding"]
    else:
        found = _finding_evidence(args.project, notary_token, args.dataset,
                                  args.window_start, args.window_end)
        finding = {
            "family": "scope-violation",
            "detector": "scope-violation@v1",
            "sql": _FINDING_SQL,
            "sessions": found["sessions"],
            # A finding is only re-checkable if a reviewer can re-run the job
            # that produced it and follow the request that triggered it. The job
            # id is BigQuery's; the trace ids come from the conduct rows
            # themselves, which is where the enforcement callback writes them.
            "job_id": found["job_id"],
            "trace_ids": found["trace_ids"],
            "table": found["table"],
        }
    verdict_link = bundle.get("verdict") or {
        "analyst": args.approver,
        "disposition": "confirmed abuse",
        "rationale": "tool calls outside the session's declared scope, repeated across tenants",
        "model_armor": "not wired until Day 5; this link carries no screening result",
    }
    draft = dict(bundle.get("draft") or {},
                 version=candidate.version,
                 rule_count=len(candidate.rules),
                 policy=json.loads(canonical_json(candidate)))

    # A bundle is a file. Every claim in it that this Notary can check itself,
    # it checks, and it refuses to write a chain rather than record a claim it
    # could not stand behind. An adversarial pass wrote a bundle asserting a
    # detector job that never ran, a screening that never happened and a 403
    # that was never taken, and the chain sealed all three as attested.
    if bundle:
        corroborate(args, notary_token, finding, verdict_link, bundle)

    # The refusal is always taken live, whatever the bundle says. The Proposer
    # reports its own 403 from the hosted service and that message is kept; what
    # is not taken on trust is that the refusal happened at all.
    denied = _live_403(args.project, args.candidate, args.current)
    claimed = bundle.get("holdout_denied")
    if claimed:
        for field in ("principal", "dataset", "permission", "http_code"):
            if str(claimed.get(field)) != str(denied.get(field)):
                raise SystemExit(
                    f"the bundle claims the Proposer was refused with "
                    f"{field}={claimed.get(field)!r}, and asking BigQuery now "
                    f"gives {denied.get(field)!r}. Nothing was written.")
        # The Proposer's own words for the refusal it received, kept verbatim,
        # now that the refusal itself has been reproduced.
        denied = dict(denied, message=claimed.get("message", denied["message"]),
                      reported_by="the Proposer, on the hosted service",
                      reproduced_by="the Notary, at seal time")

    cand_score = evidence.score(candidate)
    curr_score = evidence.score(current)
    monotone, uncovered = structurally_monotonic(candidate, current)
    gate_verdict = gate(cand_score, curr_score, monotone, uncovered,
                        evidence.widened(candidate, current))
    if not gate_verdict.passed:
        print(f"the candidate does not pass the gate ({gate_verdict.reason}); "
              f"nothing was written")
        return 1
    exam = _exam_payload(candidate, current, cand_score, curr_score, gate_verdict)

    # The refused candidates belong to the Examiner's record, because the
    # Examiner is what refused them. They are in the chain either way; putting
    # them here says who did the refusing.
    if bundle.get("refused_by_gate"):
        exam = dict(exam, refused=bundle["refused_by_gate"])

    steps = [
        ("EVIDENCE", evidence_payload),
        ("FINDING", finding),
        ("VERDICT", verdict_link),
    ]
    # Every draft the grammar refused, in the order it refused them, and BEFORE
    # the one that survived, because that is the order they happened in. A retry
    # that leaves no record turns "the model got it wrong twice" into "the model
    # got it right".
    steps.extend(("DRAFT-REJECTED", r) for r in bundle.get("rejected_drafts", []))
    steps.append(("DRAFT", draft))
    steps.append(("HOLDOUT-DENIED", denied))
    steps.append(("EXAM", exam))
    steps.append(("APPROVAL", dict(bundle.get("approval") or {},
                                   approver=args.approver,
                                   verdict=gate_verdict.reason,
                                   approves_exam_hash=None)))
    links = bind_approval(chain.build(args.version, steps))

    store.append_all(links)
    root = chain.root_of(links)
    uri = chain.seal(args.bucket, args.version, links[-1].seq, root, links, args.notary_sa)
    store.register(args.version, args.parent, canonical_json(candidate), root, uri)
    print(f"wrote {len(links)} links for {args.version}")
    print(f"root   {root}")
    print(f"sealed {uri}")
    return 0


def corroborate(args, token: str, finding: dict, verdict: dict, bundle: dict) -> None:
    """Check a bundle's claims against the systems that would have produced them.

    Three of the four links a bundle supplies name something outside this
    process: a BigQuery job, a row a human wrote through the Analyst Copilot,
    and an approval of the same kind. Each is looked up. A claim that cannot be
    corroborated stops the promotion, because the alternative is a chain that
    verifies while asserting a detector ran, a human was screened and a refusal
    was taken, none of which need have happened.

    What is NOT claimed by this: that the rows the finding cites are still what
    the job returned, or that the human meant what they typed. Verification
    re-derives the evidence and the exam and nothing else, and section 2 of the
    plan claims exactly that much.
    """
    job_id = str(finding.get("job_id") or "")
    if not job_id:
        raise SystemExit("the bundle's finding names no BigQuery job. A finding a "
                         "reviewer cannot re-run is not a finding. Nothing written.")
    location, _, bare = job_id.partition(":") if ":" in job_id else ("", "", job_id)
    url = (f"https://bigquery.googleapis.com/bigquery/v2/projects/{args.project}"
           f"/jobs/{urllib.parse.quote(bare)}"
           + (f"?location={urllib.parse.quote(location)}" if location else ""))
    try:
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=60) as response:
            job = json.load(response)
    except Exception as exc:
        raise SystemExit(
            f"the Notary could not look up job {job_id}, which the bundle's "
            f"finding cites: {type(exc).__name__}: {str(exc)[:200]}. Nothing written.")
    state = (job.get("status") or {}).get("state")
    if state != "DONE" or (job.get("status") or {}).get("errorResult"):
        raise SystemExit(f"job {job_id} is {state!r} and did not complete cleanly. "
                         f"Nothing written.")
    print(f"corroborated: BigQuery job {bare[:28]} exists and completed")

    for kind, payload, subject in (
            ("VERDICT", verdict, str(finding.get("job_id") or "")),
            ("APPROVAL", bundle.get("approval") or {}, args.version)):
        decision_id = payload.get("decision_id")
        if not decision_id:
            raise SystemExit(
                f"the bundle's {kind} names no decision id, so no row a human "
                f"wrote can be found for it. Nothing written.")
        rows = bq.query(
            f"SELECT kind, analyst, subject, disposition, rationale, ma_verdict,"
            f" approved FROM `{bq.qualified_table(args.project, 'review', 'decisions')}`"
            f" WHERE decision_id = @id",
            args.project, token, params={"id": decision_id})
        if not rows:
            raise SystemExit(
                f"{kind} decision {decision_id} is not in review.decisions. The "
                f"Analyst Copilot writes that table and nothing else may. "
                f"Nothing written.")
        row = rows[0]
        if row["kind"] != kind or row["subject"] != subject:
            raise SystemExit(
                f"{kind} decision {decision_id} is a {row['kind']} on "
                f"{row['subject']!r}, not a {kind} on {subject!r}. Nothing written.")
        if kind == "VERDICT" and row["rationale"] != payload.get("rationale"):
            raise SystemExit(
                f"the bundle's verdict text differs from the row the Copilot "
                f"wrote for {decision_id}. Nothing written.")
        if kind == "APPROVAL" and str(row.get("approved")).lower() not in ("true", "1"):
            raise SystemExit(
                f"decision {decision_id} does not record an approval of "
                f"{args.version}. Nothing written.")
        print(f"corroborated: {kind} {decision_id} was written by the Copilot "
              f"as {row['analyst']}")


_FINDING_SQL = (
    "SELECT session_id, COUNT(*) AS calls, "
    "ARRAY_AGG(DISTINCT trace_id IGNORE NULLS LIMIT 5) AS trace_ids FROM {table} "
    "WHERE ts >= TIMESTAMP(@start) AND ts < TIMESTAMP(@end) "
    "AND tool_name IS NOT NULL AND tool_name NOT IN UNNEST(declared_scope) "
    "GROUP BY session_id ORDER BY session_id"
)

# A chain link holds a bounded payload. A finding over a wide window can name
# thousands of sessions, and a link that grows without limit is a link nobody
# reads. Both lists are capped and the payload says so.
FINDING_CAP = 200


def _finding_evidence(project: str, token: str, dataset: str, start: str,
                      end: str) -> dict:
    """The finding's sessions, its trace ids, and the job that produced them.

    Run through query_job rather than query, because the job id is the point: a
    reviewer re-runs that exact job instead of taking the link's word for the
    session list.
    """
    table = f"`{bq.qualified_table(project, dataset)}`"
    rows, job_id = bq.query_job(_FINDING_SQL.format(table=table), project, token,
                                params={"start": start, "end": end})
    sessions = [r["session_id"] for r in rows]
    traces = sorted({t for r in rows for t in (r.get("trace_ids") or []) if t})
    return {
        "sessions": sessions[:FINDING_CAP],
        "sessions_total": len(sessions),
        "trace_ids": traces[:FINDING_CAP],
        "job_id": job_id,
        "table": table.strip("`"),
    }


def _live_403(project: str, candidate: str, current: str) -> dict:
    """Ask BigQuery to let proposer-sa score its own draft, and record the refusal.

    Not a stored string. The Examiner is run for real under proposer-sa and the
    payload BigQuery answers with is what goes into the link.
    """
    proposer = f"proposer-sa@{project}.iam.gserviceaccount.com"
    out = subprocess.run(
        [sys.executable, "-m", "caseharden.examiner", "--candidate", candidate,
         "--current", current, "--backend", "bq", "--project", project,
         "--impersonate", proposer],
        capture_output=True, text=True, cwd=str(REPO),
    )
    if out.returncode != 3:
        raise RuntimeError(
            f"expected the Proposer to be refused the sealed holdout (exit 3), got exit "
            f"{out.returncode}. The seal is the entry's first claim; this link is not "
            f"written from anything other than a live refusal.\n{out.stdout}{out.stderr}")
    payload = json.loads(out.stdout[out.stdout.index("{"):])
    error = payload["error"]
    return {
        "principal": proposer,
        "dataset": "holdout_sealed",
        "permission": "bigquery.tables.getData",
        "http_code": error.get("code"),
        "status": error.get("status"),
        "message": error.get("message"),
        "recorded_as": "evidence of what the system refused, not of what it did",
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="The Caseharden Notary.")
    parser.add_argument("--project", default=os.environ.get("CASEHARDEN_PROJECT",
                                                            "devpost-hackathon-506416"))
    parser.add_argument("--bucket", default=os.environ.get(
        "CASEHARDEN_BUCKET", "caseharden-certificates-506416"))
    parser.add_argument("--impersonate", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify")
    v.add_argument("--version", required=True)
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("reattest")
    r.add_argument("--version", required=True)
    r.set_defaults(func=cmd_reattest)

    p = sub.add_parser("promote")
    p.add_argument("--version", required=True)
    p.add_argument("--parent", required=True)
    p.add_argument("--candidate", required=True)
    p.set_defaults(func=cmd_promote)

    c = sub.add_parser("certificate")
    c.add_argument("--version", required=True)
    c.add_argument("--out", default="out/certificate.html")
    c.set_defaults(func=cmd_certificate)

    s = sub.add_parser("seed")
    s.add_argument("--version", required=True)
    s.add_argument("--parent", default="v3")
    s.add_argument("--candidate", required=True)
    s.add_argument("--current", default=str(REPO / "policies" / "v3-active.json"))
    s.add_argument("--dataset", default="conduct_train")
    s.add_argument("--window-start", default="2026-08-14T00:00:00Z")
    s.add_argument("--window-end", default="2026-08-15T00:00:00Z")
    s.add_argument("--approver", default="analyst@caseharden.example")
    s.add_argument("--bundle", default=None,
                   help="JSON from infra/110_run_loop.py: the finding, verdict, "
                        "refused drafts and the Proposer's own 403")
    s.set_defaults(func=cmd_seed)

    g = sub.add_parser("genesis")
    g.add_argument("--version", required=True)
    g.add_argument("--policy", required=True)
    g.set_defaults(func=cmd_genesis)

    args = parser.parse_args(argv)
    if not bq.NAME_RE.match(args.project):
        print(f"not a usable project id: {args.project!r}")
        return 2
    try:
        return args.func(args)
    except bq.BigQueryError as exc:
        print(f"BIGQUERY REFUSED. {exc}")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
