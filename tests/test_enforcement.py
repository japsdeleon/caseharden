#!/usr/bin/env python3
"""The shared enforcement callback: what it blocks, and what it claims about it.

No network and no model. The Policy Server is a dict, Model Armor is a function,
and the sink is a list, so every branch is reachable offline on the same
interpreter as the rest of the repo.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from agents.common import enforcement  # noqa: E402
from agents.common.enforcement import ATTESTED, QUARANTINED, UNKNOWN  # noqa: E402
from caseharden.dsl import parse  # noqa: E402

POLICY = {
    "version": "v4",
    "rules": [
        {"id": "cross-tenant-tool-call", "action": "deny", "reason": "egress",
         "all_of": [{"op": "present", "field": "tool_name"}, {"op": "tenant_mismatch"}]},
        {"id": "tool-call-on-injected-turn", "action": "deny", "reason": "injection",
         "all_of": [{"op": "present", "field": "tool_name"},
                    {"op": "at_least", "field": "ma_prompt_injection_score",
                     "value": 0.75}]},
    ],
}

CLEAN = {"event_id": "e1", "session_id": "s1", "turn_index": 0,
         "tenant_id": "t_014", "declared_scope": ["lookup_order"],
         "tool_name": "lookup_order", "turn_text": "where is my order"}
CROSS = dict(CLEAN, event_id="e2", target_tenant_id="t_room9")


class FakeClient:
    """A Policy Server that answers whatever the test says it answers."""

    def __init__(self, answer):
        self.answer = answer

    def active(self):
        return enforcement._normalise(self.answer)


def served(state="ATTESTED", attested=True, policy=POLICY, **extra):
    return dict({"version": "v4", "policy": policy, "state": state,
                 "attested": attested, "promotions": "OPEN"}, **extra)


def enforcer(answer, armor=None, sink=None):
    return enforcement.Enforcer("support-agent", FakeClient(answer),
                                armor=armor, sink=sink)


# --------------------------------------------------------------------------
# The distinction the whole entry rests on
# --------------------------------------------------------------------------

def test_a_block_under_an_attested_version_claims_no_caveat():
    """The regression that shipped to Cloud Run and was caught by the proof.

    The server sends "ATTESTED"; the constant here is "attested". Comparing them
    directly made every block unattested, so the refusal read "policy state
    ATTESTED - cannot currently be justified from evidence".
    """
    decision = enforcer(served()).decide(CROSS)
    assert decision.allowed is False
    assert decision.reason_attested is True
    assert "UNATTESTED" not in decision.message()
    assert decision.message() == "cross-tenant-tool-call denied by conduct policy v4"


def test_the_state_is_compared_case_insensitively():
    for state in ("ATTESTED", "attested", "Attested"):
        assert enforcer(served(state=state)).decide(CROSS).reason_attested is True


def test_a_block_under_a_quarantined_version_still_blocks():
    """Attestation gates authority, not availability."""
    decision = enforcer(served(state="QUARANTINED", attested=False)).decide(CROSS)
    assert decision.allowed is False
    assert decision.attestation_state == QUARANTINED


def test_a_block_under_a_quarantined_version_cannot_be_justified():
    decision = enforcer(served(state="QUARANTINED", attested=False)).decide(CROSS)
    assert decision.reason_attested is False
    assert "UNATTESTED" in decision.message()
    assert "QUARANTINED" in decision.message()


def test_attested_true_with_a_non_attested_state_is_not_believed():
    """Both halves have to agree. Either one alone is a claim, not a check."""
    assert enforcer(served(state="QUARANTINED", attested=True)).decide(CROSS).reason_attested is False
    assert enforcer(served(state="ATTESTED", attested=False)).decide(CROSS).reason_attested is False


def test_an_allow_never_carries_an_attestation():
    """An allow asserts nothing, so there is nothing for the record to back."""
    decision = enforcer(served()).decide(CLEAN)
    assert decision.allowed is True
    assert decision.reason_attested is False


# --------------------------------------------------------------------------
# Degraded modes
# --------------------------------------------------------------------------

class Unreachable:
    def __init__(self):
        self.calls = 0

    def active(self):
        raise OSError("connection refused")


def test_with_no_policy_ever_fetched_the_call_is_refused():
    client = enforcement.PolicyClient("http://127.0.0.1:1")
    decision = enforcement.Enforcer("a", client).decide(CLEAN)
    assert decision.allowed is False
    assert decision.rule == "NO-POLICY"
    assert decision.attestation_state == UNKNOWN


def test_the_last_good_policy_keeps_enforcing_when_the_server_goes_away(monkeypatch):
    """A guardrail that evaporates when its control plane blips is not a guardrail."""
    client = enforcement.PolicyClient("http://example.invalid")
    monkeypatch.setattr(client, "_get", lambda path: served())
    assert client.active()["state"] == "attested"

    monkeypatch.setattr(client, "_get",
                        lambda path: (_ for _ in ()).throw(OSError("gone")))
    answer = client.active()
    assert answer["policy"] == POLICY
    assert answer["state"] == UNKNOWN
    assert answer["attested"] is False
    assert answer["stale"] is True

    decision = enforcement.Enforcer("a", client).decide(CROSS)
    assert decision.allowed is False
    assert decision.reason_attested is False
    assert decision.source == "stale"


def test_a_malformed_policy_document_does_not_let_the_call_through():
    with pytest.raises(Exception):
        enforcer(served(policy={"version": "v4", "rules": [{"nonsense": True}]})).decide(CROSS)


# --------------------------------------------------------------------------
# Screening
# --------------------------------------------------------------------------

def test_screening_fields_reach_the_policy():
    armor = lambda text: {"ma_prompt_injection_score": 0.95,
                          "ma_jailbreak_score": 0.95, "ma_verdict": "BLOCK"}
    decision = enforcer(served(), armor=armor).decide(CLEAN)
    assert decision.rule == "tool-call-on-injected-turn"


def broken_armor(text):
    raise RuntimeError("model armor is down")


def test_a_screening_failure_refuses_a_call_the_policy_cannot_evaluate():
    """An Armor outage must not become a bypass for the rule Armor feeds.

    The first version of this test asserted `allowed is True` and called it
    correct, on the grounds that no other rule in the policy denied the call.
    That codified a fail-open: the one rule that would have denied it was the
    one that could not be evaluated.
    """
    rows = []
    decision = enforcer(served(), armor=broken_armor, sink=rows.append).decide(CLEAN)
    assert decision.allowed is False
    assert decision.rule == enforcement.SCREENING_UNAVAILABLE
    assert decision.reason_attested is False
    assert "screening is unavailable" in decision.message()
    assert rows[0]["ma_verdict"] == "SCREENING_FAILED"
    assert rows[0]["ma_prompt_injection_score"] is None


def test_a_screening_failure_does_not_refuse_a_policy_that_never_needed_it():
    """Only the rules that depend on screening are affected by losing it."""
    no_armor_rules = {"version": "v3", "rules": [POLICY["rules"][0]]}
    decision = enforcer(served(policy=no_armor_rules),
                        armor=broken_armor).decide(CLEAN)
    assert decision.allowed is True
    assert enforcement.needs_screening(parse(no_armor_rules)) is False
    assert enforcement.needs_screening(parse(POLICY)) is True


def test_a_screening_failure_is_never_recorded_as_justified():
    rows = []
    enforcer(served(), armor=broken_armor, sink=rows.append).decide(CLEAN)
    assert rows[0]["decision"] == "DENY"
    assert rows[0]["decision_attested"] is False


def test_a_turn_with_no_text_is_unscreened_not_clean():
    """The bypass an audit drove a refund through.

    screen() returned {} for an empty turn, which is the same shape a turn that
    was never sent to Armor produces, so the SCREENING_FAILED guard never fired
    and the injection rule could not match a missing field. The conduct row was
    also indistinguishable afterwards from a turn that screened clean.
    """
    screened = enforcer(served(), armor=lambda t: {"ma_verdict": "BLOCK"}).screen("")
    assert screened["ma_verdict"] == "NOT_SCREENED"


def test_a_tool_call_on_an_unscreened_turn_is_refused():
    for event in (dict(CLEAN, turn_text=""), {k: v for k, v in CLEAN.items()
                                              if k != "turn_text"}):
        decision = enforcer(served(),
                            armor=lambda t: {"ma_prompt_injection_score": 0.95,
                                             "ma_verdict": "BLOCK"}).decide(event)
        assert decision.allowed is False, event
        assert decision.rule == enforcement.SCREENING_UNAVAILABLE
        assert decision.reason_attested is False


def test_an_unscreened_turn_is_allowed_when_no_rule_needs_screening():
    no_armor_rules = {"version": "v3", "rules": [POLICY["rules"][0]]}
    decision = enforcer(served(policy=no_armor_rules),
                        armor=lambda t: {"ma_verdict": "BLOCK"}).decide(
                            dict(CLEAN, turn_text=""))
    assert decision.allowed is True


# --------------------------------------------------------------------------
# The staleness bound
# --------------------------------------------------------------------------

def test_past_the_staleness_bound_the_call_is_refused(monkeypatch):
    """STALE_SECONDS has to bound something or it is decoration.

    Promotions only ever narrow, so an indefinitely old policy is a permissive
    one. The flag was set and never read; enforcing onward for ever was the
    quiet default.
    """
    import time as _time

    client = enforcement.PolicyClient("http://example.invalid")
    monkeypatch.setattr(client, "_get", lambda path: served())
    client.active()
    monkeypatch.setattr(client, "_get",
                        lambda path: (_ for _ in ()).throw(OSError("gone")))
    client._last_at = _time.time() - (enforcement.STALE_SECONDS + 1)

    answer = client.active()
    assert answer["expired"] is True
    decision = enforcement.Enforcer("a", client).decide(CROSS)
    assert decision.allowed is False
    assert decision.rule == enforcement.POLICY_EXPIRED
    assert decision.source == "expired"


def test_inside_the_staleness_bound_the_last_policy_still_enforces(monkeypatch):
    client = enforcement.PolicyClient("http://example.invalid")
    monkeypatch.setattr(client, "_get", lambda path: served())
    client.active()
    monkeypatch.setattr(client, "_get",
                        lambda path: (_ for _ in ()).throw(OSError("gone")))
    decision = enforcement.Enforcer("a", client).decide(CROSS)
    assert decision.allowed is False
    assert decision.rule == "cross-tenant-tool-call"
    assert decision.source == "stale"


def test_a_derived_trace_id_is_labelled_as_derived():
    """Cloud Trace holds nothing for these ids, and the code says so."""
    derived = enforcement.trace_id_for("s1", 2)
    assert enforcement.derived_trace_id(derived, "s1", 2) is True
    assert enforcement.derived_trace_id("f" * 32, "s1", 2) is False


# --------------------------------------------------------------------------
# The record
# --------------------------------------------------------------------------

def test_the_recorded_row_carries_the_whole_decision():
    rows = []
    armor = lambda text: {"ma_prompt_injection_score": 0.95,
                          "ma_jailbreak_score": 0.95, "ma_verdict": "BLOCK"}
    enforcer(served(state="QUARANTINED", attested=False), armor=armor,
             sink=rows.append).decide(CLEAN)
    row = rows[0]
    assert row["decision"] == "DENY"
    assert row["decision_rule"] == "tool-call-on-injected-turn"
    assert row["decision_attested"] is False
    assert row["attestation_state"] == QUARANTINED
    assert row["policy_version"] == "v4"
    assert len(row["trace_id"]) == 32
    assert row["ma_prompt_injection_score"] == 0.95


def test_a_sink_failure_never_turns_a_block_into_an_allow():
    def broken(row):
        raise RuntimeError("bigquery is down")

    decision = enforcer(served(), sink=broken).decide(CROSS)
    assert decision.allowed is False


def test_the_trace_id_is_stable_for_the_same_turn():
    a = enforcement.trace_id_for("s1", 3)
    b = enforcement.trace_id_for("s1", 3)
    assert a == b and len(a) == 32
    assert enforcement.trace_id_for("s1", 4) != a


# --------------------------------------------------------------------------
# What reaches the warehouse
# --------------------------------------------------------------------------

def test_only_real_columns_are_written():
    """An allowlist, so a new diagnostic field cannot stop the event stream.

    tabledata.insertAll rejects a whole row that carries a column the table does
    not have, and the callback attaches ma_error on a screening failure.
    """
    from agents.common import conduct

    row = conduct._clean({"event_id": "e1", "tool_name": "issue_refund",
                          "ma_error": "TimeoutError: model armor",
                          "whatever": 1, "decision": "DENY"})
    assert row == {"event_id": "e1", "tool_name": "issue_refund", "decision": "DENY"}


def test_the_answer_key_columns_are_never_written():
    """Live traffic has no ground truth, so a column for it could only be guessed."""
    from agents.common import conduct

    row = conduct._clean({"event_id": "e1", "label": "abuse", "is_attack_event": True})
    assert row == {"event_id": "e1"}
    assert "label" not in conduct.COLUMNS
    assert "is_attack_event" not in conduct.COLUMNS


def test_the_column_allowlist_matches_the_deployed_table_schema():
    """The allowlist and the table are two files. This is what keeps them equal."""
    import json

    from agents.common import conduct

    here = os.path.dirname(os.path.abspath(__file__))
    schema = json.load(open(os.path.join(here, "..", "infra", "schema_turns_live.json")))
    assert list(conduct.COLUMNS) == [f["name"] for f in schema]


# --------------------------------------------------------------------------
# Screening translation
# --------------------------------------------------------------------------

def test_a_high_band_crosses_the_shipped_threshold():
    """HIGH is the only band that does. The policies key on 0.75."""
    from agents.common import armor

    fields = armor.to_fields({"sanitizationResult": {
        "filterMatchState": "MATCH_FOUND",
        "filterResults": {"pi_and_jailbreak": {"piAndJailbreakFilterResult": {
            "matchState": "MATCH_FOUND", "confidenceLevel": "HIGH"}}}}})
    assert fields["ma_prompt_injection_score"] == 0.95
    assert fields["ma_prompt_injection_score"] >= 0.75
    assert fields["ma_verdict"] == "BLOCK"


def test_a_medium_band_does_not_cross_it_on_its_own():
    from agents.common import armor

    fields = armor.to_fields({"sanitizationResult": {
        "filterMatchState": "MATCH_FOUND",
        "filterResults": {"pi_and_jailbreak": {"piAndJailbreakFilterResult": {
            "matchState": "MATCH_FOUND", "confidenceLevel": "MEDIUM_AND_ABOVE"}}}}})
    assert fields["ma_prompt_injection_score"] < 0.75


def test_no_match_scores_zero_and_allows():
    from agents.common import armor

    fields = armor.to_fields({"sanitizationResult": {
        "filterMatchState": "NO_MATCH_FOUND",
        "filterResults": {"pi_and_jailbreak": {"piAndJailbreakFilterResult": {
            "matchState": "NO_MATCH_FOUND"}}}}})
    assert fields["ma_prompt_injection_score"] == 0.0
    assert fields["ma_verdict"] == "ALLOW"


# --------------------------------------------------------------------------
# Signing the fan-out
# --------------------------------------------------------------------------

def test_the_token_audience_drops_a_default_port():
    """ADK renders a card URL as https://host:443 and Cloud Run wants https://host."""
    from agents.common import auth

    assert auth.origin("https://x.run.app:443/a2a/y") == "https://x.run.app"
    assert auth.origin("http://x.example:80/a") == "http://x.example"
    assert auth.origin("http://localhost:8099/a") == "http://localhost:8099"
