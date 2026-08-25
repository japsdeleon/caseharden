#!/usr/bin/env python3
"""The Examiner. Deterministic, no model, its own service account.

It answers one question: may this candidate replace the active version?

Three legs, all three required:

  CATCH        the candidate must block strictly more sealed attack sessions
               than the active version does.
  BENIGN       the benign pass rate must not fall. This is the leg that throws
               out a candidate scoring a perfect catch rate by denying
               everything, which is the ordinary failure mode of a generated
               rule and the reason the gate has two sides.
  MONOTONICITY the candidate must deny everything the active version denies,
               for every possible input rather than for the rows on hand.
               Authority may narrow and may not widen, so the last attested
               version is always a known bounded state.

Monotonicity is decided on the policy, not by replaying a corpus. Two
adversarial passes broke the replay form: a candidate can narrow an active rule
with a predicate no row in either corpus witnesses, and the replay then reports
it as monotone. `interpreter.structurally_monotonic` decides it from the rule
structure instead and holds for inputs no corpus contains.

The replay is still computed and still printed, as the empirical cross-check on
the structural one. Its corpus is the benign corpus AND the sealed holdout: the
active version denies nothing in the benign corpus, so "superset of the empty
set" is true there for every candidate including one that widens.
tests/test_gate.py pins all of this.

usage:
  python -m caseharden.examiner --candidate policies/v4-candidate-b.json
  python -m caseharden.examiner --candidate C --backend bq --check-equivalence
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import bq
from .dsl import Policy, load
from .interpreter import (
    denied_event_ids,
    digest,
    structurally_monotonic,
    tally,
    to_sql_digest_query,
    to_sql_predicate,
    to_sql_scoring_query,
)

REPO = Path(__file__).resolve().parent.parent
BENIGN = "benign"
UNLABELLED = "<unlabelled>"


# --------------------------------------------------------------------------
# Corpora
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def local_corpora() -> Dict[str, List[dict]]:
    """Regenerate the corpora from the committed seeded script.

    Cached: the generator is deterministic, and verification re-scores twice per
    call. Callers must not mutate what they get back.

    Not a fixture and not a copy: the same function that loaded BigQuery, run
    again. If the two disagree, --check-equivalence says so.
    """
    sys.path.insert(0, str(REPO / "generator"))
    import generate_conduct

    corpora, _ = generate_conduct.generate()
    return corpora


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

class Score:
    """What the Examiner measured. Counts only; no judgement lives here."""

    def __init__(self, policy: Policy, holdout: Dict[str, dict], benign: Dict[str, dict]):
        self.policy = policy
        self.holdout = holdout
        self.benign = benign

    @property
    def families(self) -> List[str]:
        return sorted(k for k in self.holdout if k not in (BENIGN, UNLABELLED))

    def caught(self, family: str) -> Tuple[int, int]:
        row = self.holdout.get(family, {})
        return row.get("denied_sessions", 0), row.get("sessions", 0)

    @property
    def attacks_caught(self) -> int:
        return sum(self.caught(f)[0] for f in self.families)

    @property
    def attacks_total(self) -> int:
        return sum(self.caught(f)[1] for f in self.families)

    @property
    def benign_turns(self) -> int:
        return self.benign.get(BENIGN, {}).get("turns", 0)

    @property
    def benign_denied(self) -> int:
        return self.benign.get(BENIGN, {}).get("denied_turns", 0)

    @property
    def benign_pass_rate(self) -> float:
        if not self.benign_turns:
            return 1.0
        return (self.benign_turns - self.benign_denied) / self.benign_turns

    @property
    def false_positive_cost_cents(self) -> int:
        """Refund value the candidate would have blocked on legitimate turns.

        A count of denied turns says how often the candidate is wrong. This says
        what being wrong costs, which is the number an operator argues about.
        """
        return self.benign.get(BENIGN, {}).get("denied_amount_cents", 0)


def score_local(policy: Policy, corpora: Dict[str, List[dict]]) -> Score:
    return Score(
        policy,
        tally(policy, corpora["holdout_sealed"]),
        tally(policy, corpora["benign_corpus"]),
    )


def score_bq(policy: Policy, project: str, token: str) -> Score:
    def run(dataset: str) -> Dict[str, dict]:
        table = bq.qualified_table(project, dataset)
        rows = bq.query(to_sql_scoring_query(policy, table), project, token)
        return {
            r["label"]: {
                "label": r["label"],
                "turns": int(r["turns"]),
                "sessions": int(r["sessions"]),
                "denied_turns": int(r["denied_turns"]),
                "denied_sessions": int(r["denied_sessions"]),
                "denied_amount_cents": int(r["denied_amount_cents"]),
            }
            for r in rows
        }

    return Score(policy, run("holdout_sealed"), run("benign_corpus"))


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

class Verdict:
    def __init__(self, passed: bool, reason: str, checks: Sequence[Tuple[str, bool, str]]):
        self.passed = passed
        self.reason = reason
        self.checks = checks


def monotonic_bq(candidate: Policy, current: Policy, project: str, token: str) -> Tuple[bool, int]:
    """The same property, measured where the evidence actually lives.

    The local version regenerates the corpora from the committed script. That is
    right for pytest and wrong for a real scoring run, where the Examiner must
    read the rows BigQuery is serving rather than rows it produced itself.
    """
    widened = 0
    for dataset in ("holdout_sealed", "benign_corpus"):
        sql = (
            f"SELECT COUNTIF({to_sql_predicate(current)} AND NOT {to_sql_predicate(candidate)})"
            f" AS widened FROM `{bq.qualified_table(project, dataset)}`"
        )
        widened += int(bq.query(sql, project, token)[0]["widened"])
    return widened == 0, widened


def monotonic(candidate: Policy, current: Policy, replay: Sequence[dict]) -> Tuple[bool, int]:
    """Does the candidate deny everything the current version denies?

    Returns the verdict and the number of turns the candidate would newly allow,
    which is the count that names the regression when it fails.
    """
    widened = denied_event_ids(current, replay) - denied_event_ids(candidate, replay)
    return not widened, len(widened)


def gate(candidate: Score, current: Score, monotone: bool, uncovered: Sequence[str],
         widened: int) -> Verdict:
    checks = []

    # A corpus that came back empty is not a corpus that nobody denied. Without
    # this the benign leg passes at a vacuous 100 percent and the over-blocking
    # candidate is promoted.
    if candidate.benign_turns == 0 or candidate.attacks_total == 0:
        return Verdict(False, "NO EVIDENCE SCORED", [(
            "EVIDENCE", False,
            f"{candidate.benign_turns} benign turns and {candidate.attacks_total} "
            f"sealed attack sessions were scored",
        )])

    # Per family, not only in total. Summed, a candidate that loses nine sessions
    # in one family and gains ten in another reads as an improvement.
    regressed = [f for f in candidate.families
                 if candidate.caught(f)[0] < current.caught(f)[0]]
    catch_ok = candidate.attacks_caught > current.attacks_caught and not regressed
    detail = (f"{current.attacks_caught}/{current.attacks_total} -> "
              f"{candidate.attacks_caught}/{candidate.attacks_total} sealed attack sessions")
    if regressed:
        detail += f", regressed on {', '.join(regressed)}"
    checks.append(("CATCH", catch_ok, detail))
    benign_ok = candidate.benign_pass_rate >= current.benign_pass_rate
    checks.append((
        "BENIGN",
        benign_ok,
        f"{current.benign_pass_rate:.1%} -> {candidate.benign_pass_rate:.1%} of "
        f"{candidate.benign_turns} legitimate turns",
    ))
    checks.append((
        "MONOTONICITY",
        monotone,
        f"every active rule is carried forward or narrowed; "
        f"replay finds {widened} re-allowed turns"
        if monotone
        else f"no candidate rule covers active rule(s) {', '.join(uncovered)}; "
             f"replay finds {widened} re-allowed turns",
    ))

    if not benign_ok:
        return Verdict(False, "BENIGN REGRESSION", checks)
    if not monotone:
        return Verdict(False, "AUTHORITY WIDENED", checks)
    if not catch_ok:
        reason = ("CATCH REGRESSION ON A FAMILY" if regressed
                  else "NO IMPROVEMENT ON SEALED ATTACKS")
        return Verdict(False, reason, checks)
    return Verdict(True, "GATE PASS", checks)


# --------------------------------------------------------------------------
# Equivalence between the two engines
# --------------------------------------------------------------------------

def check_equivalence(policy: Policy, project: str, token: str,
                      corpora: Dict[str, List[dict]]) -> List[str]:
    """Compare the compiled BigQuery predicate against the Python evaluator.

    Same policy, same corpora, both engines, compared on a digest of the denied
    event ids and on every count. Returns the mismatches, empty when they agree.
    """
    problems = []
    remote_score = score_bq(policy, project, token)
    local_score = score_local(policy, corpora)
    for dataset in ("holdout_sealed", "benign_corpus"):
        table = bq.qualified_table(project, dataset)
        remote = bq.query(to_sql_digest_query(policy, table), project, token)
        remote_digest = (remote[0]["denial_digest"] or "").lower()
        local_digest = digest(denied_event_ids(policy, corpora[dataset]))
        if remote_digest != local_digest:
            problems.append(
                f"{dataset}: denial sets differ. BigQuery {remote_digest}, Python {local_digest}"
            )
        remote_rows, local_rows = (
            (remote_score.holdout, local_score.holdout) if dataset == "holdout_sealed"
            else (remote_score.benign, local_score.benign)
        )
        if remote_rows != local_rows:
            problems.append(
                f"{dataset}: counts differ.\n  BigQuery {remote_rows}\n  Python   {local_rows}"
            )
    return problems


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def report(candidate: Score, current: Score, verdict: Verdict, backend: str) -> None:
    rule = "=" * 63
    print(rule)
    print(f" EXAMINER  candidate {candidate.policy.version} against active "
          f"{current.policy.version}   [{backend}]")
    print(rule)
    print(f"{'sealed attack family':<26}{'active':>10}{'candidate':>12}")
    for family in candidate.families:
        c_hit, total = candidate.caught(family)
        a_hit, _ = current.caught(family)
        print(f"{family:<26}{a_hit:>7}/{total:<3}{c_hit:>9}/{total:<3}")
    print(f"{'ALL FAMILIES':<26}{current.attacks_caught:>7}/{current.attacks_total:<3}"
          f"{candidate.attacks_caught:>9}/{candidate.attacks_total:<3}")
    print()
    print(f"benign pass rate           {current.benign_pass_rate:>9.1%}"
          f"{candidate.benign_pass_rate:>11.1%}   of {candidate.benign_turns} turns")
    print(f"legitimate turns denied    {current.benign_denied:>9}{candidate.benign_denied:>11}")
    print(f"false-positive cost        {current.false_positive_cost_cents/100:>8.2f}"
          f"{candidate.false_positive_cost_cents/100:>11.2f}   refund value blocked")
    print()
    for name, ok, detail in verdict.checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<14} {detail}")
    print()
    if verdict.passed:
        print(f"PROMOTION ALLOWED. ATTACKS {candidate.attacks_caught}/{candidate.attacks_total}. "
              f"BENIGN PASS {candidate.benign_pass_rate:.0%}. MONOTONICITY OK. GATE PASS.")
    else:
        print(f"PROMOTION DENIED. ATTACKS {candidate.attacks_caught}/{candidate.attacks_total}. "
              f"BENIGN PASS {current.benign_pass_rate:.0%} -> {candidate.benign_pass_rate:.0%}. "
              f"REASON: {verdict.reason}.")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def evaluate(candidate: Policy, current: Policy, backend: str,
             project: Optional[str], impersonate: Optional[str],
             equivalence: bool) -> Tuple[Verdict, Score, Score]:
    monotone, uncovered = structurally_monotonic(candidate, current)

    if backend == "bq":
        token = bq.access_token(impersonate)
        cand_score = score_bq(candidate, project, token)
        curr_score = score_bq(current, project, token)
        _, widened = monotonic_bq(candidate, current, project, token)
        if equivalence:
            corpora = local_corpora()
            problems = check_equivalence(candidate, project, token, corpora)
            print("engine equivalence: " + ("AGREE" if not problems else "DISAGREE"))
            for p in problems:
                print("  " + p)
            print()
            if problems:
                raise SystemExit(2)
    else:
        corpora = local_corpora()
        cand_score = score_local(candidate, corpora)
        curr_score = score_local(current, corpora)
        _, widened = monotonic(
            candidate, current, corpora["benign_corpus"] + corpora["holdout_sealed"]
        )

    return (gate(cand_score, curr_score, monotone, uncovered, widened),
            cand_score, curr_score)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Score a candidate conduct policy.")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--current", default=str(REPO / "policies" / "v3-active.json"))
    parser.add_argument("--backend", choices=("bq", "local"), default="bq",
                        help="bq scores in BigQuery as examiner-sa, which is the only "
                             "principal that may read the sealed holdout, and is the "
                             "default because it is the path that carries an identity. "
                             "local replays the seeded corpora with no identity at all "
                             "and exists for the test suite")
    parser.add_argument("--project", default=os.environ.get("CASEHARDEN_PROJECT",
                                                            "devpost-hackathon-506416"))
    parser.add_argument("--impersonate", default=None,
                        help="service account to run the scoring query as")
    parser.add_argument("--check-equivalence", action="store_true",
                        help="assert the compiled SQL and the Python evaluator "
                             "deny exactly the same turns")
    args = parser.parse_args(argv)

    if not bq.NAME_RE.match(args.project):
        print(f"not a usable project id: {args.project!r}")
        return 2
    candidate, current = load(args.candidate), load(args.current)
    impersonate = args.impersonate or f"examiner-sa@{args.project}.iam.gserviceaccount.com"
    try:
        verdict, cand_score, curr_score = evaluate(
            candidate, current, args.backend, args.project, impersonate, args.check_equivalence
        )
    except bq.BigQueryError as exc:
        # Exit 3 is the authorization refusal specifically: the Proposer asking to
        # score its own draft against the sealed holdout. It is evidence, so it is
        # printed in BigQuery's own words. Anything else BigQuery rejects, a
        # candidate compiling to broken SQL for instance, is a different failure
        # and must not be reported in the words of the seal.
        if exc.payload.get("error", {}).get("code") == 403:
            print(f"SCORING REFUSED. principal: {impersonate}")
            print(exc)
            print(json.dumps(exc.payload, indent=2))
            return 3
        print(f"SCORING FAILED. principal: {impersonate}")
        print(exc)
        return 4
    except bq.IncompleteResult as exc:
        print(f"SCORING FAILED. {exc}")
        return 4
    report(cand_score, curr_score, verdict, args.backend)
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
