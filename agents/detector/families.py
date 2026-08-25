#!/usr/bin/env python3
"""The four conduct checks, as SQL. One template, four parameter sets.

A detector does not evaluate the active policy. If it did, it could only ever
find conduct the fleet already blocks, and the loop would have nothing to feed.
Its job is the opposite: surface conduct that is happening, whether or not any
rule currently denies it, so a rule can be argued for.

Detection is SQL, not a model. Each check returns rows and the BigQuery job id
that produced them, and that job id is written into the chain's FINDING link. A
reviewer re-runs the job rather than trusting the summary. The model attached to
each detector writes the summary and nothing else; it cannot invent a row,
because the rows do not come from it.
"""

from __future__ import annotations

import re
from typing import Dict

# Every check is bounded by the same partition filter and the same row cap. An
# unbounded scan against a growing table is how a detector becomes the most
# expensive thing in the project.
WINDOW_HOURS_DEFAULT = 72
ROW_CAP = 200

# Which tools read and which tools write, for the sequencing check. Constants,
# not caller input: they are interpolated into SQL.
READ_TOOLS = ("lookup_order", "lookup_account", "search_orders", "get_ticket")
WRITE_TOOLS = ("issue_refund", "update_account", "close_ticket", "apply_credit")

# project.dataset.table, and nothing else. Backticks, spaces, semicolons and
# quotes are all absent from this character class on purpose.
TABLE_RE = re.compile(r"^[a-z][a-z0-9_-]{2,60}\.[A-Za-z0-9_]{1,1024}\.[A-Za-z0-9_]{1,1024}$")

FAMILIES: Dict[str, dict] = {
    "cross-tenant": {
        "title": "Cross-tenant tool calls",
        "description": (
            "A tool call whose target tenant is not the tenant the session "
            "belongs to. The egress case: whatever the turn said, the call "
            "reached another customer's data."),
        "predicate": ("tool_name IS NOT NULL AND target_tenant_id IS NOT NULL "
                      "AND target_tenant_id != tenant_id"),
    },
    "scope-escape": {
        "title": "Calls outside the declared scope",
        "description": (
            "The session declared which tools it may use and then called one "
            "outside that list. The only pattern the active v3 policy already "
            "denies, kept in the fleet so the roster shows an enforced check "
            "next to three unenforced ones."),
        "predicate": ("tool_name IS NOT NULL "
                      "AND tool_name NOT IN UNNEST(declared_scope)"),
    },
    "injected-turn": {
        "title": "Tool calls on screened-injection turns",
        "description": (
            "A tool call on a turn Model Armor scored as a prompt injection. "
            "The screening happened; nothing acted on it."),
        "predicate": ("tool_name IS NOT NULL "
                      "AND ma_prompt_injection_score >= 0.75"),
    },
    "privilege-sequencing": {
        "title": "Read-then-write privilege sequencing",
        "description": (
            "A session that wrote to an account it never read. The agent used a "
            "read tool to move around, then called a write tool against an "
            "account no read in that session ever touched. No individual call "
            "is anomalous, which is the point: this is a sequence, and no "
            "per-event predicate in the policy DSL can express it."),
        # Both lists are constants in this file. The predicate below bounds the
        # scan to tool calls; the sequencing itself is in `having`.
        "predicate": "tool_name IS NOT NULL",
        "sequencing": True,
    },
}


def scan_sql(family: str, table: str, window_hours: int = WINDOW_HOURS_DEFAULT) -> str:
    """The check's query. Parameterless by construction: no caller value reaches it.

    The predicate is a constant in this file and the window is an integer this
    function formats itself. `table` is validated HERE rather than trusted to
    have been validated by the caller: the docstring used to claim the caller
    had done it, and a claim in a docstring is not a check. A backtick in the
    table name closes the identifier and appends whatever follows to the query.
    """
    if not TABLE_RE.match(table):
        raise ValueError(f"not a usable table identifier: {table!r}")
    spec = FAMILIES[family]
    window = int(window_hours)
    if not 1 <= window <= 24 * 30:
        raise ValueError(f"window out of range: {window_hours!r}")
    where = (f"ts >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {window} HOUR) "
             f"AND {spec['predicate']}")

    if spec.get("sequencing"):
        # Two CTEs rather than a window function: BigQuery refuses IGNORE NULLS
        # on an analytic ARRAY_AGG ("Analytic function array_agg does not
        # support IGNORE NULLS or RESPECT NULLS"), and without IGNORE NULLS the
        # read set fills with nulls and every write matches.
        #
        # A write with no account at all does not count. Absent is not "some
        # other account", and guessing which it was is how a detector invents a
        # finding.
        reads = ", ".join(f"'{t}'" for t in READ_TOOLS)
        writes = ", ".join(f"'{t}'" for t in WRITE_TOOLS)
        return (
            "WITH calls AS ("
            "  SELECT session_id, tenant_id, event_id, turn_index, tool_name, "
            "         account_id, trace_id, ts "
            f"  FROM `{table}` WHERE {where}"
            "), touched AS ("
            "  SELECT session_id, "
            "         ARRAY_AGG(DISTINCT account_id IGNORE NULLS) AS read_accounts "
            f"  FROM calls WHERE tool_name IN ({reads}) GROUP BY session_id"
            ") "
            "SELECT c.session_id, ANY_VALUE(c.tenant_id) AS tenant_id, "
            "COUNT(*) AS hits, "
            "ARRAY_AGG(c.event_id ORDER BY c.ts LIMIT 20) AS event_ids, "
            "ARRAY_AGG(DISTINCT c.trace_id IGNORE NULLS LIMIT 5) AS trace_ids, "
            "ARRAY_AGG(DISTINCT c.account_id IGNORE NULLS LIMIT 10) AS unread_accounts, "
            "MAX(c.ts) AS last_ts "
            "FROM calls c LEFT JOIN touched t USING (session_id) "
            f"WHERE c.tool_name IN ({writes}) AND c.account_id IS NOT NULL "
            "  AND c.account_id NOT IN UNNEST("
            "        IFNULL(t.read_accounts, ARRAY<STRING>[])) "
            "GROUP BY c.session_id "
            f"ORDER BY hits DESC LIMIT {ROW_CAP}"
        )
    if "group_by" in spec:
        return (
            "SELECT session_id, tenant_id, COUNT(*) AS hits, "
            "ARRAY_AGG(event_id ORDER BY ts LIMIT 20) AS event_ids, "
            "ARRAY_AGG(DISTINCT trace_id IGNORE NULLS LIMIT 5) AS trace_ids, "
            "SUM(IFNULL(amount_cents, 0)) AS total_cents, MAX(ts) AS last_ts "
            f"FROM `{table}` WHERE {where} "
            f"GROUP BY session_id, tenant_id HAVING {spec['having']} "
            f"ORDER BY hits DESC LIMIT {ROW_CAP}"
        )
    return (
        "SELECT event_id, session_id, tenant_id, target_tenant_id, tool_name, "
        "amount_cents, ma_prompt_injection_score, trace_id, ts "
        f"FROM `{table}` WHERE {where} "
        f"ORDER BY ts DESC LIMIT {ROW_CAP}"
    )
