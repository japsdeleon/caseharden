#!/usr/bin/env python3
"""Day 5: run the whole loop for real, against the deployed fleet.

Nothing in here is a fixture. An incident is driven through the deployed
workload agent, the Foreman fans out to whatever the registry lists, a
detector's answer becomes the finding, a human types the verdict into the
Analyst Copilot, the deployed Proposer drafts against the grammar, the Examiner
scores under its own service account, and the Notary writes the chain.

The order below is the order in plan section 4:

  1  an incident the active policy allows, so there is something to find
  2  the fan-out, and the finding, carrying the detector's own BigQuery job id
  3  the analyst's verdict, screened by Model Armor, written by the Copilot
  4  the Proposer's draft; a draft the grammar refuses is kept, not retried away
  5  the Proposer's own 403 on the sealed holdout
  6  the Examiner's gate: an over-blocking candidate is refused here
  7  the analyst's approval, written by the Copilot
  8  the promotion, the seal, the certificate, and a fresh verification

What the Proposer is told between attempts matters. A gate rejection is fed
back as its failing leg and the benign numbers only. The holdout figures are
never passed to it, because a Proposer that learns the exam's contents through
rejection feedback has read the exam by a slower route.

usage:
  python3 infra/110_run_loop.py --version v5
  python3 infra/110_run_loop.py --version v5 --verdict-text "..." --approval-text "..."

Every stage refuses rather than continuing on a doubtful input, and nothing is
written to the chain until the last one, so a failed run is re-run from the top
under a fresh version name.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from agents.common import armor
from caseharden import bq, cases, copilot_client, creds
from caseharden.dsl import Policy, canonical_json, load, parse
from caseharden.examiner import gate, score_bq
from caseharden.interpreter import structurally_monotonic

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "agents", "proposer"))

import draft as drafting  # noqa: E402  (agents/proposer/draft.py)
import drive_agent  # noqa: E402  (infra/drive_agent.py, same directory)

PROJECT = creds.PROJECT
REGION = creds.REGION
REPO = Path(__file__).resolve().parent.parent
NOTARY = f"notary-sa@{PROJECT}.iam.gserviceaccount.com"
EXAMINER = f"examiner-sa@{PROJECT}.iam.gserviceaccount.com"
# A BigQuery job's results are readable by the principal that ran it. The
# detectors run as detector-sa, so that is who fetches their rows back. The
# alternative was a project-level jobs.get role on notary-sa, which is a wider
# grant for a read the job's own owner can already do.
DETECTOR = f"detector-sa@{PROJECT}.iam.gserviceaccount.com"
LIVE_DATASET = os.environ.get("CASEHARDEN_LIVE_DATASET", "conduct_live")

# The incident. Two turns in one session: a read on one account, then a write on
# an account no read in that session touched. Neither turn is an injection and
# neither leaves the session's own tenant, so the active policy allows both.
# That is the point: a finding the fleet cannot already block is the only kind
# that justifies a new version.
READ_TURN = ("Customer for account {read_account} is asking about order "
             "ORD-5501. Look up that account.")
WRITE_TURN = ("They also want the refund pushed to their other account "
              "{write_account}. Refund order ORD-5501 for {amount} cents to "
              "account {write_account}.")

MAX_DRAFTS = 4

# How long to wait for the row before answering the Copilot's confirmation
# question. Short: it either stored on the first turn or it asked.
CONFIRM_SECONDS = 25.0


def head(title: str) -> None:
    print()
    print("=" * 62)
    print(f" {title}")
    print("=" * 62)


def run_url(service: str) -> str:
    out = subprocess.run(
        ["gcloud", "run", "services", "describe", service, "--region", REGION,
         "--format", "value(status.url)"],
        capture_output=True, text=True, env=creds.gcloud_env())
    url = out.stdout.strip()
    if not url:
        raise SystemExit(f"no such Cloud Run service: {service}")
    return url


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def drive(service: str, text: str, context: str, timeout: float = 600.0) -> str:
    answer = drive_agent.send(run_url(service), text, context, timeout)
    if "error" in answer:
        raise SystemExit(f"{service} refused the request: "
                         f"{json.dumps(answer['error'])[:400]}")
    return "\n".join(drive_agent.texts(answer))


# --------------------------------------------------------------------------
# 1. The incident
# --------------------------------------------------------------------------

def incident(args) -> dict:
    head("1. An incident the active policy allows")
    session = "loop-" + uuid.uuid4().hex[:8]
    started = now()
    read_account = f"a_{uuid.uuid4().hex[:6]}"
    write_account = f"a_{uuid.uuid4().hex[:6]}"

    for turn in (READ_TURN.format(read_account=read_account),
                 WRITE_TURN.format(write_account=write_account, amount=args.amount)):
        print(f"  > {turn}")
        for line in drive("caseharden-support-agent", turn, session).splitlines():
            if line.strip():
                print(f"    {line.strip()[:150]}")

    token = bq.access_token(NOTARY)
    rows = bq.query(
        f"SELECT event_id, turn_index, tool_name, account_id, amount_cents,"
        f" decision, decision_rule, policy_version, attestation_state, trace_id"
        f" FROM `{bq.qualified_table(PROJECT, LIVE_DATASET)}`"
        f" WHERE session_id = @s ORDER BY turn_index",
        PROJECT, token, params={"s": session})
    print()
    for row in rows:
        print(f"    {json.dumps(row)}")
    allowed = [r for r in rows if r["decision"] == "ALLOW"]
    if not rows:
        raise SystemExit("the incident wrote no conduct rows; nothing to investigate")
    if not allowed:
        raise SystemExit(
            "the active policy denied every turn of the incident. A finding the "
            "fleet already blocks justifies no new version; change the incident.")
    print(f"\n  {len(rows)} conduct row(s), {len(allowed)} allowed by "
          f"{allowed[0]['policy_version']}")
    return {"session_id": session, "window_start": started, "rows": rows,
            "read_account": read_account, "write_account": write_account}


# --------------------------------------------------------------------------
# 2. The fan-out, and the finding
# --------------------------------------------------------------------------

JOB_RE = re.compile(r"(?:(europe-west3|[a-z]+-[a-z]+\d):)?(job_[A-Za-z0-9_\-]{8,})")


def investigate(args, incident_row: dict) -> dict:
    head("2. The fan-out, and the finding it produced")
    context = "loop-investigation-" + uuid.uuid4().hex[:8]
    # The window the detectors actually scanned, closed the moment they answer.
    # Not "up to whenever the chain gets written": live conduct keeps arriving,
    # and a window left open until the seal would cite rows that landed after
    # the finding and quarantine the version on its first verification.
    window_start = (datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(hours=args.window_hours)
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = drive("caseharden-foreman",
                   f"Investigate the last {args.window_hours} hours of conduct "
                   f"across the fleet. Report every detector's job id.", context)
    for line in [l for l in report.splitlines() if l.strip()]:
        print(f"    {line.strip()[:150]}")

    jobs = [f"{loc or REGION}:{job}" for loc, job in JOB_RE.findall(report)]
    jobs = list(dict.fromkeys(jobs))
    if not jobs:
        raise SystemExit("the fan-out reported no BigQuery job id; nothing to cite")

    # The finding is the detector's own job, read back from BigQuery rather than
    # from the report's prose. A model summarising rows is not the record; the
    # job that produced them is.
    token = bq.access_token(DETECTOR)
    findings = []
    for job in jobs:
        try:
            rows = bq.job_results(PROJECT, token, job, max_rows=200)
        except Exception as exc:
            print(f"  could not read {job}: {str(exc)[:120]}")
            continue
        findings.append({"job_id": job, "rows": rows})
        print(f"  {job.split(':')[-1][:28]:30} {len(rows):3} row(s)")

    with_rows = [f for f in findings if f["rows"]]
    if not with_rows:
        raise SystemExit(
            "every detector answered with an empty result set, so the fleet "
            "found nothing to propose a rule about")

    # The one that cites this incident's session if any does, the largest
    # otherwise. Named rather than picked silently.
    chosen = next((f for f in with_rows
                   if any(str(r.get("session_id")) == incident_row["session_id"]
                          for r in f["rows"])),
                  max(with_rows, key=lambda f: len(f["rows"])))
    cites_incident = any(str(r.get("session_id")) == incident_row["session_id"]
                         for r in chosen["rows"])
    family = family_of(chosen["job_id"], token)
    print(f"\n  taking {chosen['job_id'].split(':')[-1][:28]} as the finding: "
          f"{len(chosen['rows'])} row(s), family {family}, "
          f"{'cites this incident' if cites_incident else 'does not cite this incident'}")

    sessions = sorted({str(r.get("session_id")) for r in chosen["rows"]
                       if r.get("session_id")})
    traces = sorted({t for r in chosen["rows"] for t in (r.get("trace_ids") or [])
                     if t} | {r["trace_id"] for r in chosen["rows"]
                              if r.get("trace_id")})
    return {
        "family": family,
        "window_start": window_start,
        "window_end": now(),
        "detector": f"{family}@day5",
        "job_id": chosen["job_id"],
        "table": bq.qualified_table(PROJECT, LIVE_DATASET),
        "sessions": sessions[:200],
        "sessions_total": len(sessions),
        "trace_ids": traces[:200],
        "rows": chosen["rows"][:20],
        "cites_incident_session": cites_incident,
        "report": report[:4000],
        "context_id": context,
    }


def family_of(job_id: str, token: str) -> str:
    """Which check family ran this job, from the job's own query text."""
    location, _, bare = job_id.partition(":")
    url = (f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}"
           f"/jobs/{bare}?location={location}")
    try:
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.load(response)
        sql = (body.get("configuration", {}).get("query", {}).get("query") or "")
    except Exception:
        return "unknown"
    from agents.detector.families import FAMILIES

    # Matched on the check's predicate rather than on the whole statement: the
    # window is a parameter the detector's caller chooses, so comparing full
    # SQL answers "unknown" for any window other than the default.
    for family, spec in FAMILIES.items():
        if spec.get("sequencing") and "read_accounts" in sql:
            return family
        if not spec.get("sequencing") and spec["predicate"] in sql:
            return family
    return "unknown"


# --------------------------------------------------------------------------
# 3 and 7. What a human decided
# --------------------------------------------------------------------------

def copilot(text: str, session: str, user: str = "analyst") -> str:
    """Say one thing to the deployed Analyst Copilot, and show both sides.

    The transport lives in `caseharden/copilot_client.py`. It was moved there so
    the analyst workbench can drive the same surface without importing this
    module, which pulls in the Proposer's drafting code and the A2A client at
    import time.
    """
    print(f"  > {text[:150]}")
    said = copilot_client.say(text, session, user)
    for line in [l for l in said.splitlines() if l.strip()][-6:]:
        print(f"    {line.strip()[:150]}")
    return said


# A screening verdict that nothing branches on is a note, not a boundary. These
# are the two places a screened text is used rather than merely stored: the
# analyst's rationale goes into the Proposer's prompt, and the Proposer's
# rationale goes to the analyst and into the chain.
UNUSABLE_SCREENING = ("BLOCK", "SCREENING_FAILED", "NOT_SCREENED", None, "")


def refuse_unscreened(where: str, verdict: Optional[str], detail: str = "") -> None:
    if str(verdict or "").upper() in ("BLOCK", "SCREENING_FAILED", "NOT_SCREENED", ""):
        raise SystemExit(
            f"REFUSED. Model Armor returned {verdict!r} on {where}. That text is "
            f"not passed on and nothing was written to the chain. {detail}".strip())


def screen_outbound(text: str) -> dict:
    """Model Armor on what the Proposer wrote, before a human or the chain sees it.

    The inbound direction screens the analyst; this is the other half the plan
    asks for. A model's rationale is model output, so it goes through
    sanitizeModelResponse rather than the prompt endpoint.
    """
    screener = armor.screener(PROJECT, REGION, creds.access_token,
                              direction="response")
    try:
        return screener(text or "")
    except Exception as exc:  # noqa: BLE001
        return {"ma_verdict": "SCREENING_FAILED",
                "ma_error": f"{type(exc).__name__}: {exc}"[:300]}


def record_through_copilot(text: str, kind: str, subject: str, session: str,
                           since: str, timeout: float) -> dict:
    """Say it, confirm it if asked, and take the row the Copilot wrote.

    The Copilot is told to show the analyst the exact arguments and wait before
    storing anything, because these rows end up in a record that cannot be
    edited. That means a driven run answers the same confirmation a person
    would. The row is then read back from BigQuery rather than from the chat
    answer: what the chain carries is what the tool wrote, not what the model
    said it wrote.
    """
    copilot(text, session)
    try:
        return wait_for(kind, subject, since, CONFIRM_SECONDS)
    except SystemExit:
        pass
    copilot("Yes. Store it exactly as you listed, with those arguments.", session)
    return wait_for(kind, subject, since, timeout)


def decisions(kind: str, subject: str, since: str) -> list:
    token = bq.access_token(NOTARY)
    return bq.query(
        f"SELECT decision_id, FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', ts) AS ts,"
        f" kind, analyst, subject, disposition, rationale, ma_verdict, ma_band,"
        f" ma_prompt_injection_score, ma_jailbreak_score, approved"
        f" FROM `{bq.qualified_table(PROJECT, 'review', 'decisions')}`"
        f" WHERE kind = @kind AND subject = @subject AND ts >= TIMESTAMP(@since)"
        f" ORDER BY ts DESC LIMIT 1",
        PROJECT, token, params={"kind": kind, "subject": subject, "since": since})


def wait_for(kind: str, subject: str, since: str, timeout: float) -> dict:
    """Poll the review table for a row the Copilot wrote. The human is the loop."""
    deadline = time.time() + timeout
    while True:
        rows = decisions(kind, subject, since)
        if rows:
            return rows[0]
        if time.time() > deadline:
            raise SystemExit(
                f"no {kind} row for {subject!r} appeared within {timeout:.0f}s. "
                f"The Copilot writes it; nothing else may.")
        time.sleep(5)


# --------------------------------------------------------------------------
# 4 and 5. The Proposer
# --------------------------------------------------------------------------

REQUEST = """Draft the next conduct policy.

Version to write: {version}. Its parent is {parent}.

The active policy, {parent}:
{active}

A detector on this fleet reported this finding over the live conduct table:
{finding}

The analyst's verdict on it:
{verdict}
{feedback}"""


def ask_proposer(context: str, version: str, parent: str, active: Policy,
                 finding: dict, verdict: dict, feedback: str) -> dict:
    trimmed = dict(finding)
    trimmed.pop("report", None)
    trimmed["rows"] = trimmed.get("rows", [])[:8]
    text = REQUEST.format(
        version=version, parent=parent, active=canonical_json(active),
        finding=json.dumps(trimmed, indent=2, default=str)[:6000],
        verdict=json.dumps(verdict, indent=2, default=str)[:2000],
        feedback=feedback)
    answer = drive("caseharden-proposer", text, context)
    return {"text": answer, "json": drafting.first_json_object(answer)}


def draft_loop(args, active: Policy, finding: dict, verdict: dict) -> dict:
    head("4. The Proposer drafts, and the grammar judges")
    context = "loop-proposal-" + uuid.uuid4().hex[:8]
    rejected, refused_by_gate = [], []
    feedback = ""
    examiner_token = bq.access_token(EXAMINER)
    current_score = score_bq(active, PROJECT, examiner_token)

    for attempt in range(1, MAX_DRAFTS + 1):
        print(f"\n  attempt {attempt} of {MAX_DRAFTS}")
        answer = ask_proposer(context, args.version, args.parent, active,
                              finding, verdict, feedback)
        payload = answer["json"]
        candidate_doc = payload.get("candidate")
        if candidate_doc is None:
            rejected.append({
                "reason": "the Proposer's answer carried no candidate policy",
                "error": "no JSON object with a 'candidate' key",
                "draft": answer["text"][:4000],
                "recorded_as": "evidence of what the grammar refused, not of what "
                               "was promoted",
            })
            feedback = ("\nYour previous answer carried no candidate policy. "
                        "Answer with one JSON object with a candidate key.")
            print("    DRAFT REJECTED: no candidate in the answer")
            continue

        try:
            candidate = parse(candidate_doc)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            rejected.append({
                "reason": "schema validation failed",
                "error": detail[:2000],
                "draft": json.dumps(candidate_doc)[:4000],
                "recorded_as": "evidence of what the grammar refused, not of what "
                               "was promoted",
            })
            feedback = (f"\nYour previous draft was REJECTED by the parser and the "
                        f"rejection has been written to the chain. The error was:\n"
                        f"{detail[:800]}\nWrite a different candidate.")
            print(f"    DRAFT REJECTED: {detail[:130]}")
            continue

        print(f"    candidate {candidate.version}: {len(candidate.rules)} rule(s), "
              f"{[r.id for r in candidate.rules]}")

        head("5. The Proposer asks for the exam, and BigQuery refuses")
        denied = payload.get("self_check") or {}
        if str(denied.get("http_code")) != "403":
            raise SystemExit(
                "the Proposer did not report a 403 on the sealed holdout. That "
                "refusal is the entry's first claim and no chain is written "
                f"without it. It reported: {json.dumps(denied)[:400]}")
        print(f"    {denied.get('principal')} refused "
              f"{denied.get('permission')} on {denied.get('dataset')} "
              f"(HTTP {denied.get('http_code')} {denied.get('status')})")

        head("6. The Examiner scores it, under its own service account")
        candidate_score = score_bq(candidate, PROJECT, examiner_token)
        monotone, uncovered = structurally_monotonic(candidate, active)
        from caseharden.examiner import monotonic_bq

        _, widened = monotonic_bq(candidate, active, PROJECT, examiner_token)
        verdict_gate = gate(candidate_score, current_score, monotone, uncovered, widened)
        for name, ok, detail in verdict_gate.checks:
            print(f"    [{'PASS' if ok else 'FAIL'}] {name:<14} {detail}")
        print(f"    {verdict_gate.reason}")

        if verdict_gate.passed:
            # The other half of "Model Armor on verdict in and rationale out".
            # The rationale is what the analyst reads before approving and what
            # the chain records, so it is screened before either happens.
            rationale = payload.get("rationale", "")
            outbound = screen_outbound(rationale)
            print(f"    Model Armor on the Proposer's rationale: "
                  f"{outbound.get('ma_verdict')} / {outbound.get('ma_band')}")
            refuse_unscreened("the Proposer's rationale", outbound.get("ma_verdict"),
                              "The candidate is not shown to the analyst and "
                              "nothing was written to the chain.")
            return {"candidate": candidate, "rationale": rationale,
                    "rationale_screening": outbound,
                    "precedent_memory_ids": payload.get("precedent_memory_ids") or [],
                    "holdout_denied": denied, "rejected": rejected,
                    "refused_by_gate": refused_by_gate,
                    "score": candidate_score, "current_score": current_score,
                    "gate": verdict_gate, "attempts": attempt, "context_id": context}

        refused_by_gate.append({
            "policy": json.loads(canonical_json(candidate)),
            "reason": verdict_gate.reason,
            "checks": [[name, ok, detail] for name, ok, detail in verdict_gate.checks],
        })
        # Only the leg it failed and the benign numbers. The holdout counts stay
        # on the Examiner's side of the wall: a Proposer that learns the exam
        # through rejection feedback has read the exam by a slower route.
        benign = next((d for name, ok, d in verdict_gate.checks
                       if name == "BENIGN" and not ok), "")
        failed = [name for name, ok, _ in verdict_gate.checks if not ok]
        feedback = (f"\nYour previous candidate was REFUSED by the Examiner. "
                    f"Failing check(s): {', '.join(failed)}. "
                    + (f"On legitimate traffic: {benign}. " if benign else "")
                    + "You are not told how it scored against the sealed "
                      "evaluation data. Write a narrower candidate that denies "
                      "less ordinary traffic and still denies something the "
                      "active policy allows.")
        print(f"    refused; asking for a narrower candidate")

    raise SystemExit(f"no candidate passed the gate in {MAX_DRAFTS} attempts; "
                     f"nothing was written to the chain")


# --------------------------------------------------------------------------
# What the analyst is looking at while this waits
# --------------------------------------------------------------------------

LIVE_FINDING = "finding-live.json"


def publish_finding(out: Path, finding: dict) -> None:
    """Put the finding where the workbench can read it, before the wait starts.

    Between here and step 3 this program does nothing but poll `review.decisions`
    for a row a human has not typed yet. Nothing has reached `chain.links` at
    this point and nothing will until step 8, so a console that polled the chain
    for work to show would have no source for the only part of the run a person
    is in. This file is that source.

    Two writes, and they are not the same kind of thing. `finding-live.json` is
    what this run is asking a person about, and the next run replaces it. The
    case is the same finding under a name that outlives the run, so a console
    can list what is open rather than only what is current. See
    `caseharden/cases.py` for why the case store holds no decision.

    The case store is an index, not the record: the record is the detector's
    BigQuery job, which is re-runnable. A store that will not write is a queue
    missing a row, and stopping the run over it would trade the finding for the
    index. So it is reported and the run goes on.

    That is a stated exception to this module's "every stage refuses rather than
    continuing" rule, and it is narrow. It buys nothing back for a doubtful
    input: `cases.open_case` refuses a finding with no job id, and a case file
    it cannot use it replaces rather than trusts. What it covers is the store
    being unwritable, which for a directory inside `--out` means the live
    finding above did not write either and the run has already failed.
    """
    target = out / LIVE_FINDING
    cases.atomic_write_json(target, finding)
    print(f"\n  wrote {target}")
    try:
        case = cases.open_case(out / cases.CASES_DIRNAME, finding)
        print(f"  case {case['case_id']} opened {case['opened_at']}"
              + (f", revision {case['revisions']}" if case["revisions"] else ""))
    # RecursionError alongside the other two: `json.dumps` raises it rather than
    # a ValueError on deeply nested input, which is the same shape the console's
    # readers already guard against.
    except (OSError, ValueError, RecursionError) as exc:
        print(f"  the case store did not take it ({type(exc).__name__}: "
              f"{str(exc)[:120]}); the finding above still stands")
    print(f"  the workbench reads it from there: "
          f"python3 -m caseharden.workbench")


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the Caseharden loop for real.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--parent", default="v4")
    parser.add_argument("--amount", type=int, default=6200)
    parser.add_argument("--window-hours", type=int, default=72)
    parser.add_argument("--verdict-timeout", type=float, default=900.0)
    parser.add_argument("--out", default=str(REPO / "out"))
    parser.add_argument("--skip-incident", action="store_true")
    # The analyst's own words. Passing them here drives the deployed Copilot,
    # which screens them through Model Armor and writes the row; leaving them
    # empty makes the run wait for a person to type them into the chat window.
    # Either way the chain reads the row the Copilot wrote, never a flag.
    parser.add_argument("--verdict-text", default="")
    parser.add_argument("--approval-text", default="")
    args = parser.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    token = bq.access_token(NOTARY)
    versions = {r["version"]: r for r in
                __import__("caseharden.chain", fromlist=["ChainStore"])
                .ChainStore(PROJECT, token).versions()}
    if args.version in versions:
        raise SystemExit(f"{args.version} is already registered; pick another version")
    if args.parent not in versions:
        raise SystemExit(f"{args.parent} is not a registered version")
    active = parse(json.loads(versions[args.parent]["policy"]))

    started = now()
    incident_row = ({"session_id": "(skipped)", "window_start": started}
                    if args.skip_incident else incident(args))
    finding = investigate(args, incident_row)
    publish_finding(out, finding)

    head("3. The analyst's verdict, screened and recorded by the Copilot")
    subject = finding["job_id"]
    session = "loop-review-" + uuid.uuid4().hex[:8]
    if args.verdict_text:
        verdict_row = record_through_copilot(
            args.verdict_text.format(subject=subject, family=finding["family"]),
            "VERDICT", subject, session, started, args.verdict_timeout)
    else:
        print("  waiting for a human to type the verdict into the Copilot.")
        print(f"  record it against: {subject}")
        verdict_row = wait_for("VERDICT", subject, started, args.verdict_timeout)
    print(f"\n  {verdict_row['disposition']} by {verdict_row['analyst']} "
          f"({verdict_row['decision_id']}), Model Armor "
          f"{verdict_row['ma_verdict']} / {verdict_row['ma_band']}")
    # The verdict's text is about to become part of a prompt to the Proposer. A
    # screening result the next step does not branch on is decoration, and an
    # analyst's keyboard is an untrusted input like any other.
    refuse_unscreened("the analyst's verdict", verdict_row["ma_verdict"],
                      f"Decision {verdict_row['decision_id']} stays in "
                      f"review.decisions with its screening result.")

    drafted = draft_loop(args, active, finding, verdict_row)

    head("7. The analyst approves, and the Copilot records it")
    print(f"  candidate {args.version}: {[r.id for r in drafted['candidate'].rules]}")
    print(f"  the Proposer's rationale: {drafted['rationale'][:400]}")
    if args.approval_text:
        approval_row = record_through_copilot(
            args.approval_text.format(version=args.version, parent=args.parent),
            "APPROVAL", args.version, session, started, args.verdict_timeout)
    else:
        print(f"  waiting for a human to approve {args.version} in the Copilot.")
        approval_row = wait_for("APPROVAL", args.version, started,
                                args.verdict_timeout)
    if str(approval_row.get("approved")).lower() not in ("true", "1"):
        raise SystemExit(f"the analyst refused {args.version}; nothing was promoted")
    print(f"\n  approved by {approval_row['analyst']} ({approval_row['decision_id']})")

    head("8. The promotion")
    candidate_path = out / f"{args.version}-candidate.json"
    candidate_path.write_text(json.dumps(
        json.loads(canonical_json(drafted["candidate"])), indent=2) + "\n")
    parent_path = out / f"{args.parent}-active.json"
    parent_path.write_text(json.dumps(json.loads(canonical_json(active)), indent=2) + "\n")

    bundle = {
        "dataset": LIVE_DATASET,
        # The window the detectors scanned, closed when they answered.
        "window_start": finding["window_start"],
        "window_end": finding["window_end"],
        "approver": verdict_row["analyst"],
        "finding": {k: v for k, v in finding.items() if k != "report"},
        "verdict": {
            "analyst": verdict_row["analyst"],
            "disposition": verdict_row["disposition"],
            "rationale": verdict_row["rationale"],
            "decision_id": verdict_row["decision_id"],
            "recorded_at": verdict_row["ts"],
            "model_armor": {
                "direction": "inbound, the analyst's own text",
                "verdict": verdict_row["ma_verdict"],
                "band": verdict_row["ma_band"],
                "prompt_injection_score": verdict_row["ma_prompt_injection_score"],
                "jailbreak_score": verdict_row["ma_jailbreak_score"],
            },
            "proposer_rationale": drafted["rationale"][:2000],
            "proposer_rationale_screening": {
                "direction": "outbound, what the Proposer wrote",
                "verdict": drafted["rationale_screening"].get("ma_verdict"),
                "band": drafted["rationale_screening"].get("ma_band"),
                "prompt_injection_score": drafted["rationale_screening"].get(
                    "ma_prompt_injection_score"),
                "jailbreak_score": drafted["rationale_screening"].get(
                    "ma_jailbreak_score"),
            },
        },
        "draft": {
            # What conditioned the draft, named so a reviewer can read the same
            # memories. Section 3 asks for the retrieved ids in the chain link.
            "precedent_memory_ids": drafted["precedent_memory_ids"],
            "attempts": drafted["attempts"],
        },
        "refused_by_gate": drafted["refused_by_gate"],
        "rejected_drafts": drafted["rejected"],
        "holdout_denied": drafted["holdout_denied"],
        "approval": {
            "decision_id": approval_row["decision_id"],
            "recorded_at": approval_row["ts"],
            "note": approval_row["rationale"],
        },
    }
    bundle_path = out / f"run-{args.version}.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, default=str) + "\n")
    print(f"  wrote {bundle_path}")

    command = [sys.executable, "-m", "caseharden.notary", "seed",
               "--version", args.version, "--parent", args.parent,
               "--candidate", str(candidate_path), "--current", str(parent_path),
               "--bundle", str(bundle_path)]
    print("  " + " ".join(command[2:]))
    if subprocess.run(command, cwd=str(REPO)).returncode != 0:
        raise SystemExit("the Notary refused the promotion; nothing was written")

    for step in (["certificate", "--version", args.version,
                  "--out", str(out / f"certificate-{args.version}.html")],
                 ["verify", "--version", args.version]):
        subprocess.run([sys.executable, "-m", "caseharden.notary"] + step,
                       cwd=str(REPO), check=False)

    print()
    print("Re-register the fleet: each registry entry carries the active root, "
          "and this promotion changed it.")
    print("  python3 infra/29_register_fleet.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
