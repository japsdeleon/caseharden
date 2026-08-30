#!/usr/bin/env python3
"""The Draftsman: grounds policy drafting in stored conduct evidence.

A drafting-side helper for the human writing the next policy version. `rot`
says which active rules still deny anything, `patterns` shows what a use
case's conduct actually looks like, `overlap` reports where a draft rule
collides with a rule some line already carries, and `draft` assembles a
candidate file through the closed DSL vocabulary.

The one boundary that matters: this tool lives on the Proposer side of the
independence wall. It reads `conduct_live` and the policy registry, and it can
never touch the sealed exam. Every number it prints carries the BigQuery job
id that produced it, so a reviewer re-runs the job instead of trusting the
print. The optional `--narrate` step is labelled model narration, never
evidence: the model suggests, it never grants — the draft must still parse and
the gate still decides.

usage:
  python -m caseharden.draftsman rot --window-days 30
  python -m caseharden.draftsman patterns --use-case payments --window-days 30
  python -m caseharden.draftsman overlap --candidate policies/v2-pay-candidate.json
  python -m caseharden.draftsman draft --version v2-pay --line payments-policy \\
      --rules drafts/v2-pay-rules.json --out policies/v2-pay.json
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from pydantic import ValidationError

from . import bq
from .chain import LINE_RE, ChainStore
from .dsl import Policy, Rule, canonical_json, load, parse


def _identity(args) -> str:
    """The drafting identity. proposer-sa holds no grant on the sealed exam."""
    sa = args.impersonate or f"proposer-sa@{args.project}.iam.gserviceaccount.com"
    if sa.startswith("examiner-sa@"):
        # The operator's own credentials could mint this token anyway; the bench
        # refusing it is the statement. Drafting never runs as the exam's one
        # reader.
        raise SystemExit(
            "REFUSED — the drafting bench does not run as the sealed exam's one "
            "reader. The wall between drafting and the exam is the point.")
    return sa


def _predicate_keys(rule: Rule) -> set:
    # The Examiner's subset trick, reimplemented rather than imported:
    # interpreter.structurally_monotonic is gate-critical and a drafting helper
    # must not become an import it depends on. A rule denies when ALL of its
    # predicates match, so fewer predicates is a broader rule, and rule A
    # covers rule B exactly when keys(A) <= keys(B). Predicates are compared as
    # canonical JSON because one carrying a list is not hashable as a model.
    return {json.dumps(p.model_dump(mode="json"), sort_keys=True) for p in rule.all_of}


def _active_rules(store: ChainStore, line: Optional[str] = None,
                  rows: Optional[Sequence[dict]] = None
                  ) -> List[Tuple[str, str, Policy]]:
    """Every active registry row as (line, version, parsed policy).

    A row written before `policy_id` existed carries NULL and belongs to
    `conduct-policy`; `active` arrives as the string BigQuery's REST encoding
    makes of a BOOL. Pass `rows` to reuse a registry read already in hand.
    """
    out = []
    for row in (rows if rows is not None else store.versions()):
        if str(row.get("active")).lower() != "true":
            continue
        owner = row.get("policy_id") or "conduct-policy"
        if line and owner != line:
            continue
        out.append((owner, row["version"], parse(row["policy"])))
    return out


def _narrate(evidence: str) -> None:
    """One model call over the deterministic report above it. Labelled, and it
    must never change the exit code or the evidence."""
    try:
        from google import genai  # noqa: F401
        from .creds import genai_client
    except ImportError:
        print("narration skipped: the google-genai library is not installed")
        return
    try:
        # Held in a variable: a temporary client can be finalized mid-request,
        # which surfaces as "the client has been closed".
        client = genai_client()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=(
                "You are helping a human draft deny rules for an agent conduct "
                "policy. The evidence below is the authority; summarize it and "
                "suggest rule shapes. You decide nothing.\n\n" + evidence))
        print()
        print("--- model narration (a suggestion, not evidence) ---")
        print(response.text)
    except Exception as exc:
        print(f"narration skipped: {exc}")


# --------------------------------------------------------------------------
# rot
# --------------------------------------------------------------------------

_ROT_SQL = (
    "SELECT decision_rule, policy_version, COUNT(*) AS denials,"
    " FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', MAX(ts)) AS last_fired"
    " FROM `{table}`"
    " WHERE decision = 'DENY' AND decision_rule IS NOT NULL"
    " AND ts >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"
    " GROUP BY decision_rule, policy_version"
)


def _rot_report(active: Sequence[Tuple[str, str, Policy]], rows: Sequence[dict],
                job_id: str, days: int, owners: dict) -> List[str]:
    # A rule id is unique within a policy, not across lines, so a denial is
    # attributed through the version that enforced it: (owning line, rule id).
    # An adversarial review showed the id-only grouping crediting one line's
    # denials to another line's same-named rule, which reads as EARNING on a
    # rule that never fired.
    fired: dict = {}
    for r in rows:
        key = (owners.get(r.get("policy_version")), r["decision_rule"])
        seen = fired.setdefault(key, {"denials": 0, "last_fired": "-"})
        seen["denials"] += int(r["denials"])
        seen["last_fired"] = max(seen["last_fired"], r["last_fired"])
    lines = [f"rule rot over the last {days} day(s) of conduct_live denials"
             f"   job {job_id}", ""]
    lines.append(f"  {'line':<18}{'version':<10}{'rule':<40}{'denials':>7}"
                 f"  {'last fired':<22}verdict")
    claimed = set()
    for line_name, version, policy in active:
        for rule in policy.rules:
            hit = fired.get((line_name, rule.id))
            claimed.add((line_name, rule.id))
            denials = hit["denials"] if hit else 0
            last = hit["last_fired"] if hit else "-"
            verdict = "EARNING" if denials else "DORMANT"
            lines.append(f"  {line_name:<18}{version:<10}{rule.id:<40}"
                         f"{denials:>7}  {last:<22}{verdict}")
    unknown = sorted(k[1] for k in set(fired) - claimed)
    if unknown:
        total = sum(v["denials"] for k, v in fired.items() if k not in claimed)
        lines.append("")
        lines.append(f"  {total} denial(s) under {len(unknown)} rule id(s) no "
                     f"active version carries; they belong to superseded "
                     f"versions: {', '.join(unknown)}")
    lines.append("")
    lines.append("  DORMANT states a rot candidate. Retirement widens authority "
                 "and stays a human decision.")
    lines.append("  Counts group denials by rule id across the versions that "
                 "enforced them; a rule id is unique within a policy.")
    return lines


def cmd_rot(args) -> int:
    token = bq.access_token(_identity(args))
    registry = ChainStore(args.project, token).versions()
    active = _active_rules(None, args.line, rows=registry)
    if not active:
        print("no active versions in the registry"
              + (f" for line {args.line}" if args.line else ""))
        return 0
    # Every version's owner, active or not: a denial recorded under a
    # superseded version still belongs to that version's line.
    owners = {r["version"]: (r.get("policy_id") or "conduct-policy")
              for r in registry}
    rows, job_id = bq.query_job(
        _ROT_SQL.format(table=bq.qualified_table(args.project, "conduct_live")),
        args.project, token, params={"days": args.window_days})
    report = _rot_report(active, rows, job_id, args.window_days, owners)
    print("\n".join(report))
    if args.narrate:
        _narrate("\n".join(report))
    return 0


# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------

# The refund-ish tool surface for the payments use case. One simple WHERE; a
# family taxonomy is the human's to propose, not this filter's.
_REFUNDISH = "(tool_name LIKE '%refund%' OR tool_name = 'issue_refund')"
_WINDOW = "ts >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"


def _patterns_report(args, token: str) -> List[str]:
    table = bq.qualified_table(args.project, args.dataset)
    where = f"WHERE {_REFUNDISH} AND {_WINDOW}"
    params = {"days": args.window_days}
    lines = [f"payments conduct over the last {args.window_days} day(s)"
             f" in {args.dataset}"]

    # decision/decision_rule are enforcement outputs and exist only on the
    # live table; the training corpus predates any decision. Asking the train
    # table for a deny share is a 400, not a zero.
    live = args.dataset == "conduct_live"
    rows, job = bq.query_job(
        f"SELECT tool_name, COUNT(*) AS calls,"
        + (f" COUNTIF(decision = 'DENY') AS denies" if live else " 0 AS denies")
        + f" FROM `{table}` {where} GROUP BY tool_name ORDER BY calls DESC",
        args.project, token, params=params)
    lines += ["", f"  tool volume{' and deny share' if live else ''}   job {job}"]
    for r in rows:
        calls, denies = int(r["calls"]), int(r["denies"])
        lines.append(f"    {r['tool_name']:<28}{calls:>7} call(s)"
                     + (f"  {denies:>5} denied ({denies / max(calls, 1):.0%})"
                        if live else "  (no decisions recorded here)"))

    rows, job = bq.query_job(
        f"SELECT COUNT(*) AS calls, APPROX_QUANTILES(amount_cents, 4) AS quartiles,"
        f" MAX(amount_cents) AS top FROM `{table}` {where}",
        args.project, token, params=params)
    lines += ["", f"  amount_cents distribution   job {job}"]
    for r in rows:
        # BigQuery's REST encoding wraps each repeated value as {"v": ...}.
        quartiles = ", ".join(
            str(q.get("v") if isinstance(q, dict) else q)
            for q in (r.get("quartiles") or []))
        lines.append(f"    {int(r['calls'])} call(s), quartiles [{quartiles}],"
                     f" max {r['top']}")

    rows, job = bq.query_job(
        f"SELECT session_id, COUNT(*) AS calls,"
        f" LOGICAL_OR(target_tenant_id IS NOT NULL"
        f" AND target_tenant_id != tenant_id) AS cross_tenant"
        f" FROM `{table}` {where} GROUP BY session_id"
        f" HAVING COUNT(*) >= 3 ORDER BY calls DESC LIMIT 10",
        args.project, token, params=params)
    lines += ["", f"  sessions with 3+ refund-ish calls, top 10   job {job}"]
    for r in rows:
        flag = ("  CROSS-TENANT"
                if str(r.get("cross_tenant")).lower() == "true" else "")
        lines.append(f"    {r['session_id']:<28}{int(r['calls']):>4} call(s){flag}")

    lines += ["", "  These numbers are the evidence a human proposes a family "
                  "taxonomy from. The tool proposes nothing itself."]
    return lines


def cmd_patterns(args) -> int:
    if args.dataset in ("holdout_sealed", "benign_corpus"):
        print(f"REFUSED — {args.dataset} is exam material, and the drafting "
              f"bench never reads the exam.")
        return 2
    if args.use_case != "payments":
        print(f"the only use case wired is payments; {args.use_case!r} has "
              f"no query set")
        return 2
    token = bq.access_token(_identity(args))
    report = _patterns_report(args, token)
    print("\n".join(report))
    if args.narrate:
        _narrate("\n".join(report))
    return 0


# --------------------------------------------------------------------------
# overlap
# --------------------------------------------------------------------------

def overlap_report(draft: Policy,
                   active: Sequence[Tuple[str, str, Policy]]) -> List[str]:
    """Every (draft rule, active rule) pair whose predicate sets nest.

    Deny-only algebra means no semantic contradiction is possible; duplication
    and ownership are the real conflicts. A report, never a gate.
    """
    lines = []
    for rule in draft.rules:
        draft_keys = _predicate_keys(rule)
        for line_name, version, policy in active:
            for active_rule in policy.rules:
                active_keys = _predicate_keys(active_rule)
                if active_keys == draft_keys:
                    verdict = ("DUPLICATE — the same predicate set already "
                               "exists in that line")
                elif active_keys <= draft_keys:
                    verdict = ("COVERED — that line already denies everything "
                               "this draft rule denies; the draft rule is "
                               "redundant")
                elif draft_keys < active_keys:
                    verdict = (f"WIDER — the draft denies a superset of that "
                               f"rule; an ownership question for {line_name}")
                else:
                    continue
                lines.append(f"{rule.id} vs {line_name}/{version}/"
                             f"{active_rule.id}: {verdict}")
    return lines or ["no active rule overlaps any draft rule"]


def cmd_overlap(args) -> int:
    candidate = load(args.candidate)
    token = bq.access_token(_identity(args))
    active = _active_rules(ChainStore(args.project, token))
    for line in overlap_report(candidate, active):
        print(line)
    return 0


# --------------------------------------------------------------------------
# draft
# --------------------------------------------------------------------------

def cmd_draft(args) -> int:
    if not LINE_RE.match(args.line):
        print(f"not a usable policy line name: {args.line!r}")
        return 2
    raw = json.loads(Path(args.rules).read_text())
    rules = raw.get("rules") if isinstance(raw, dict) else raw
    try:
        # Validated before anything is read or written: a hallucinated field
        # cannot parse, and pydantic's own message names it.
        policy = parse({"version": args.version, "rules": rules})
    except ValidationError as exc:
        print(exc)
        print(f"nothing written to {args.out}")
        return 2

    token = bq.access_token(_identity(args))
    active = _active_rules(ChainStore(args.project, token))
    print("overlap against the active registry:")
    for line in overlap_report(policy, active):
        print(f"  {line}")
    print()

    Path(args.out).write_text(canonical_json(policy) + "\n")
    print(f"wrote {args.out}")
    print(f"  line     {args.line}")
    print(f"  version  {args.version}")
    print(f"  rules    {len(policy.rules)}")
    print("  the gate and a human approval still stand between this file "
          "and authority")
    # The line lives in the registry, not in the document, so the handoff into
    # the governed lifecycle is the next command, stated rather than implied.
    print(f"  next     python3 -m caseharden.notary promote --version "
          f"{args.version} --parent <parent> --candidate {args.out} "
          f"--policy-id {args.line}")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="The Caseharden Draftsman.")
    parser.add_argument("--project", default=os.environ.get(
        "CASEHARDEN_PROJECT", "devpost-hackathon-506416"))
    parser.add_argument("--impersonate", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("rot", help="per-rule denial counts across active lines")
    r.add_argument("--window-days", type=int, required=True)
    r.add_argument("--line", default=None)
    r.add_argument("--narrate", action="store_true")
    r.set_defaults(func=cmd_rot)

    p = sub.add_parser("patterns", help="grounded conduct research for a use case")
    p.add_argument("--use-case", required=True)
    p.add_argument("--window-days", type=int, required=True)
    p.add_argument("--dataset", default="conduct_live")
    p.add_argument("--narrate", action="store_true")
    p.set_defaults(func=cmd_patterns)

    o = sub.add_parser("overlap", help="draft rules against every active line")
    o.add_argument("--candidate", required=True)
    o.set_defaults(func=cmd_overlap)

    d = sub.add_parser("draft", help="assemble and validate a candidate policy")
    d.add_argument("--version", required=True)
    d.add_argument("--line", required=True)
    d.add_argument("--rules", required=True,
                   help="a JSON list of rules, or a full policy document")
    d.add_argument("--out", required=True)
    d.set_defaults(func=cmd_draft)

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
