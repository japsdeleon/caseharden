#!/usr/bin/env python3
"""One detector. Four deployments. The check family is an environment variable.

There is no per-family source file and no per-family class, because there is no
per-family behaviour: a check is a SQL predicate and a description, and both live
in families.py. Adding a fifth conduct check is a row in that table and a deploy,
not a code change, which is the same property the Foreman has about detectors.

The model here writes prose and nothing else. It is handed rows it cannot alter
and a BigQuery job id it did not choose, and its instruction forbids it from
reporting a count it was not given. Detection is the SQL; the model is the
summary. That split is the reason a finding can be re-checked by re-running one
job rather than by trusting a paragraph.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from google.adk.agents import LlmAgent

from caseharden import bq, creds

# ADK reads Application Default Credentials. On this build machine those were
# an unrelated employer identity, so nothing starts until ADC is checked.
creds.guard_ambient()
from families import FAMILIES, WINDOW_HOURS_DEFAULT, scan_sql

FAMILY = os.environ.get("CASEHARDEN_CHECK_FAMILY", "cross-tenant")
if FAMILY not in FAMILIES:
    raise SystemExit(f"unknown check family {FAMILY!r}; "
                     f"expected one of {', '.join(sorted(FAMILIES))}")

SPEC = FAMILIES[FAMILY]
PROJECT = creds.PROJECT
REGION = creds.REGION
MODEL = os.environ.get("CASEHARDEN_MODEL", "gemini-3.5-flash")
LIVE_TABLE = bq.qualified_table(PROJECT, os.environ.get("CASEHARDEN_LIVE_DATASET",
                                                        "conduct_live"), "turns")


def scan_conduct(window_hours: int = WINDOW_HOURS_DEFAULT) -> dict:
    """Run this detector's conduct check over the recent window.

    Args:
        window_hours: How far back to look, in hours. Between 1 and 720.

    Returns:
        A dict with the family, the row count, up to 200 matching rows, the
        BigQuery job id that produced them, and the exact SQL that ran.
    """
    try:
        sql = scan_sql(FAMILY, LIVE_TABLE, window_hours)
    except (KeyError, ValueError) as exc:
        return {"family": FAMILY, "error": str(exc), "count": 0, "rows": []}
    try:
        rows, job_id = bq.query_job(sql, PROJECT, creds.access_token(),
                                    location=os.environ.get("CASEHARDEN_BQ_LOCATION",
                                                            REGION))
    except Exception as exc:
        # A detector that cannot read says so. Reporting zero findings because
        # the query failed is the same output as a clean window, and the fleet
        # has no way to tell those apart afterwards.
        return {"family": FAMILY, "error": f"{type(exc).__name__}: {exc}"[:400],
                "count": 0, "rows": [], "scanned": False}
    return {
        "family": FAMILY,
        "title": SPEC["title"],
        "count": len(rows),
        "rows": rows,
        "job_id": job_id,
        "sql": sql,
        "table": LIVE_TABLE,
        "window_hours": int(window_hours),
        "scanned": True,
        "truncated": len(rows) >= 200,
    }


INSTRUCTION = f"""You are the {SPEC['title']} conduct detector for a support-agent fleet.

Your check: {SPEC['description']}

On every request, call scan_conduct exactly once, then report what it returned.

Rules you may not break:
- Report only counts and identifiers that appear in the tool result. Never
  estimate, round, or infer a number the tool did not give you.
- Always quote the job_id verbatim. A reviewer re-runs that job to check you.
- If the result has "scanned": false, say the check could not run and give the
  error. Do not report zero findings; a failed scan and a clean window are
  different answers.
- If "truncated" is true, say the result was capped at 200 rows.
- You do not decide whether anything should be blocked. You have not been told
  which conduct policy is active and you must not guess. Describe what the rows
  show and stop.

- Always name the event ids, or the session ids for a grouped check. A count
  with no identifiers cannot be acted on and cannot be checked. If there are
  more than five, give five and say how many there are in total.

Answer in at most six lines: the family, the count, the job id, the identifiers,
and the most specific thing the rows have in common. No preamble."""

root_agent = LlmAgent(
    model=MODEL,
    name=FAMILY.replace("-", "_") + "_detector",
    description=SPEC["description"],
    instruction=INSTRUCTION,
    tools=[scan_conduct],
)
