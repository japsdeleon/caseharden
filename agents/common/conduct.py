#!/usr/bin/env python3
"""Where a live conduct event is written, and why it is not written next to the corpus.

Live events go to `conduct_live.turns`, not to `conduct_train.turns`, and the
reason is measured rather than stylistic. Chain link 1 hashes each cited row as
`SHA256(TO_JSON_STRING(t))`, and `TO_JSON_STRING` emits a key for every column
including the null ones. Adding the three decision columns this table needs to
`conduct_train` would therefore change the digest of every row already cited and
quarantine every chain in the project at once.

That behaviour is correct. A schema change under a cited window really is an
evidence change. It is just not something to trigger by accident, so the live
table carries the extra columns and the cited window stays the shape it was
sealed in.
"""

from __future__ import annotations

import os
from typing import Callable, List, Optional

from caseharden import bq

DATASET = os.environ.get("CASEHARDEN_LIVE_DATASET", "conduct_live")
TABLE = "turns"

# conduct_train's columns, plus what enforcement decided and whether the record
# could back it. Kept in step with infra/schema_turns_live.json by a test.
EXTRA_COLUMNS = ("attestation_state", "decision", "decision_rule", "decision_attested")

COLUMNS = (
    "event_id",
    "ts",
    "session_id",
    "turn_index",
    "agent_id",
    "tenant_id",
    "declared_scope",
    "tool_name",
    "target_tenant_id",
    "account_id",
    "amount_cents",
    "turn_text",
    "ma_prompt_injection_score",
    "ma_jailbreak_score",
    "ma_verdict",
    "trace_id",
    "policy_version",
    "attestation_state",
    "decision",
    "decision_rule",
    "decision_attested",
)


def sink(project: str, token_fn: Callable[[], str],
         dataset: str = DATASET, table: str = TABLE) -> Callable[[dict], None]:
    """A callable that writes one decided event. Wired into Enforcer as `sink`."""

    def write(row: dict) -> None:
        bq.insert_rows([_clean(row)], project, dataset, table, token_fn())

    return write


def _clean(row: dict) -> dict:
    """Keep only real columns, by name.

    An allowlist, not a denylist. tabledata.insertAll rejects a row carrying a
    column the table does not have, and the enforcement callback attaches
    diagnostic keys such as ma_error that belong in a log and not in the
    warehouse. Filtering by what the table has means a new diagnostic field can
    never silently stop the whole event stream from landing.

    `label` and `is_attack_event` are absent from COLUMNS on purpose. They are
    ground truth, they exist in the sealed holdout, and a live event has none.
    """
    return {k: v for k, v in row.items() if k in COLUMNS}
