#!/usr/bin/env python3
"""Prove the Analyst Copilot's session flow standalone, before anything is built on it.

The workbench's verdict pane is a thin chat over `caseharden/copilot_client.py`:
create an ADK session, POST `/run` with an identity token for the service, read
the parts back. That flow is the one part of the console that cannot be tested
offline, so it is proved here first and the console is built on it second.

Three things are checked, and the second is the one that actually breaks:

  1  a session can be created, and a first message comes back with text
  2  a SECOND message on the SAME session works. ADK answers 400 or 409 for a
     session that already exists, which is the ordinary case for every turn
     after the first. A client that treats that as an error works once and then
     stops, and a chat surface is nothing but turns after the first.
  3  nothing was written to `review.decisions`. This script asks a question. If
     asking a question stores a row, the Copilot is recording without being
     told to and the console must not be pointed at it.

Check 3 needs `notary-sa` to read the review table. Pass --no-write-check to
skip it if that impersonation is not available; the check is then reported as
skipped rather than passed.

usage:
  python3 infra/115_prove_copilot_session.py
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from caseharden import bq, creds
from caseharden.copilot_client import SERVICE, say, service_url

PROJECT = creds.PROJECT
NOTARY = f"notary-sa@{PROJECT}.iam.gserviceaccount.com"

# Neither turn asks for anything to be stored, and the second one says so twice.
# The Copilot is instructed to show its arguments and wait for confirmation, so a
# row appearing here would mean that instruction is not holding.
FIRST = ("Do not record anything. Answer in one sentence: what are the two "
         "things you can record, and what do you need from me first?")
SECOND = ("Still do not record anything. Confirm you are the same session: "
          "what did I ask you a moment ago?")


def review_row_count() -> int:
    rows = bq.query(
        f"SELECT COUNT(*) AS n FROM `{bq.qualified_table(PROJECT, 'review', 'decisions')}`",
        PROJECT, bq.access_token(NOTARY))
    return int(rows[0]["n"])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-write-check", action="store_true")
    args = parser.parse_args(argv)

    session = "probe-" + uuid.uuid4().hex[:8]
    failures = []

    print(f"caseharden copilot session probe   session={session}")
    base = service_url()
    print(f"  {SERVICE}  {base}")
    print()

    before = None
    if not args.no_write_check:
        try:
            before = review_row_count()
            print(f"  review.decisions holds {before} row(s) before this probe")
        except Exception as exc:  # noqa: BLE001
            print(f"  could not read review.decisions: {str(exc)[:160]}")
            print("  the write check will be reported as skipped, not as passed")

    for label, text in (("first turn, new session", FIRST),
                        ("second turn, existing session", SECOND)):
        started = time.time()
        try:
            answer = say(text, session)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            print(f"  FAIL  {label}  {type(exc).__name__}: {str(exc)[:200]}")
            continue
        elapsed = time.time() - started
        if not answer.strip():
            failures.append(f"{label}: the reply carried no text")
            print(f"  FAIL  {label}  {elapsed:.1f}s, no text in the reply")
            continue
        print(f"  ok    {label}  {elapsed:.1f}s, {len(answer)} chars")
        for line in [l for l in answer.splitlines() if l.strip()][:3]:
            print(f"          {line.strip()[:140]}")

    write_check_ran = False
    if before is not None:
        after = review_row_count()
        if after == before:
            print(f"  ok    nothing was written: review.decisions still holds {after}")
            write_check_ran = True
        else:
            failures.append(
                f"the probe wrote {after - before} row(s) to review.decisions "
                f"without being asked to")
            print(f"  FAIL  review.decisions went from {before} to {after}")
            write_check_ran = True
    else:
        print("  ....  the write check did not run. It is not a pass.")

    print()
    if failures:
        print(f"  {len(failures)} CHECK(S) FAILED")
        for failure in failures:
            print(f"    - {failure}")
        print()
        print("  The workbench's verdict pane is built on this flow. If it does not")
        print("  hold, type the verdict into the Copilot's own chat window instead")
        print("  and let the console display the review row appearing.")
        return 1

    # The success line says only what was actually checked. An earlier version
    # printed "stores nothing it was not asked to store" whenever the two chat
    # turns worked, including when the write check had been skipped, which is
    # the claim this script exists to make and the one it had not made.
    if write_check_ran:
        print("  ALL HELD. The session flow carries two turns, and nothing was")
        print("  written to review.decisions.")
        return 0
    print("  The session flow carries two turns. The write check DID NOT RUN, so")
    print("  whether the Copilot stores rows it was not asked to store is unknown.")
    print("  Re-run with access to review.decisions before relying on that half.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
