#!/usr/bin/env python3
"""Insert one ordinary conduct event into a window a promoted version cited.

Not an attack. A late-arriving row, which is what a real streaming pipeline
produces every day. The point of the demo beat is that this is enough: the
version can no longer prove it was justified, so it loses its standing while
continuing to enforce.

A streamed row cannot be deleted by DML for roughly 90 minutes after it lands,
so this is one-way within a rehearsal. That is intentional. The remedy is
`caseharden reattest`, not an undo.

usage: python3 infra/tamper.py [--event-id e_88214] [--at 2026-08-14T23:59:00Z]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from caseharden import bq  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--project", default=os.environ.get("PROJECT", "devpost-hackathon-506416"))
parser.add_argument("--dataset", default="conduct_train")
parser.add_argument("--event-id", default="e_88214")
parser.add_argument("--at", default="2026-08-14T23:59:00Z")
parser.add_argument("--impersonate", default=None)
args = parser.parse_args()

# The workload agent is the writer of conduct events, so the late row arrives
# from the pipeline that writes every other row. Nobody attacked anything.
principal = args.impersonate or f"workload-sa@{args.project}.iam.gserviceaccount.com"
row = {
    "event_id": args.event_id,
    "ts": args.at,
    "session_id": f"s_late_{args.event_id}",
    "turn_index": 0,
    "agent_id": "support-agent",
    "tenant_id": "t_007",
    "declared_scope": ["lookup_account", "issue_refund"],
    "tool_name": "lookup_account",
    "target_tenant_id": "t_007",
    "account_id": "a_00042",
    "turn_text": "customer asks for the balance on their account",
    "ma_prompt_injection_score": 0.01,
    "ma_jailbreak_score": 0.01,
    "ma_verdict": "PASS",
}
bq.insert_rows([row], args.project, args.dataset, "turns", bq.access_token(principal))
print(f"streamed {args.event_id} into {args.dataset}.turns at {args.at}")
