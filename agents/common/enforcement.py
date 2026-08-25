#!/usr/bin/env python3
"""The shared enforcement callback. Every agent in the fleet routes tool calls here.

Three things happen per tool call, in this order, and the order is load-bearing:

1. Model Armor screens the turn. Its verdict fields are first-class predicates in
   the policy DSL, so screening has to finish before the policy can be evaluated.
2. The active policy is fetched from the Policy Server and evaluated against the
   event. A denying rule blocks the call.
3. The event is written to the live conduct table with the trace id, the policy
   version, and the attestation state that was in force at the moment of the
   decision.

The part worth reading is what happens when the policy that produced a block is
not attested. The block still happens. Availability is not the thing attestation
gates, and an audit layer that switches guardrails off when its own paperwork
lapses is a worse failure than the one it detects. What lapses is the *claim*:
the decision is recorded with `reason_attested = false`, and the caller is told
the rule is blocking without being able to say it is justified. That is the whole
thesis at the point where it costs something.

Standard library only, and no ADK import. This module is the part that has to be
correct, so it stays testable without a model, without a network, and on the same
interpreter as the rest of the repo.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional, Sequence

# Attestation states, as the Policy Server reports them.
ATTESTED = "attested"
QUARANTINED = "quarantined"
UNKNOWN = "unknown"

# What the fleet does when the Policy Server itself cannot be reached. It is not
# "allow", and it is not "fail closed on everything" either: the last policy this
# process successfully fetched keeps enforcing, marked unattested, because a
# guardrail that evaporates when its control plane blips is not a guardrail.
STALE_SECONDS = int(os.environ.get("CASEHARDEN_STALE_SECONDS", "900"))


class Decision:
    """What the callback decided, and how much of it the record can justify."""

    def __init__(self, allowed: bool, rule: Optional[str], policy_version: Optional[str],
                 attestation_state: str, reason_attested: bool, trace_id: str,
                 armor: Optional[dict] = None, source: str = "live",
                 detail: str = ""):
        self.allowed = allowed
        self.rule = rule
        self.policy_version = policy_version
        self.attestation_state = attestation_state
        # True only when a block is both in force AND derivable from attested
        # evidence. An allow carries no claim, so it is never "attested".
        self.reason_attested = reason_attested
        self.trace_id = trace_id
        self.armor = armor or {}
        self.source = source
        self.detail = detail

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "rule": self.rule,
            "policy_version": self.policy_version,
            "attestation_state": self.attestation_state,
            "reason_attested": self.reason_attested,
            "trace_id": self.trace_id,
            "source": self.source,
            "detail": self.detail,
        }

    def message(self) -> str:
        """What the workload tells its caller. Refuses to overclaim."""
        if self.allowed:
            return ""
        if self.rule == POLICY_EXPIRED:
            return (f"refused: the last conduct policy this agent could fetch "
                    f"({self.policy_version}) is older than the staleness bound "
                    f"and the policy server is unreachable")
        if self.rule == SCREENING_UNAVAILABLE:
            return (f"refused by conduct policy {self.policy_version}: this "
                    f"policy requires prompt screening and screening is "
                    f"unavailable, so the call cannot be evaluated")
        base = f"{self.rule} denied by conduct policy {self.policy_version}"
        if self.reason_attested:
            return base
        return (f"{base} (reason UNATTESTED: policy state "
                f"{self.attestation_state.upper()} — still enforcing, "
                f"cannot currently be justified from evidence)")


def trace_id_for(session_id: str, turn_index: int) -> str:
    """A 32-hex Cloud Trace id, derived so a re-run of the same turn reproduces it."""
    seed = f"{session_id}:{turn_index}".encode()
    return hashlib.sha256(seed).hexdigest()[:32]


def current_trace_id() -> Optional[str]:
    """The ambient trace id, if this process is inside a real recorded span.

    Returns None when there is not one, and the caller then derives an id from
    the session and turn instead. The two are NOT interchangeable and the
    difference matters: a derived id is a stable correlation key across the
    chain link, the conduct row and the finding, and it is not a handle Cloud
    Trace can resolve. An audit found every recorded id was derived and that
    Cloud Trace held nothing, while the docs claimed a link opened a real
    execution DAG. Exporting spans to Cloud Trace is not wired; until it is,
    `derived_trace_id` says so.
    """
    header = os.environ.get("CASEHARDEN_TRACE_HEADER", "")
    if header:
        # X-Cloud-Trace-Context: TRACE_ID/SPAN_ID;o=1
        return header.split("/", 1)[0].strip() or None
    try:
        from opentelemetry import trace as _trace

        context = _trace.get_current_span().get_span_context()
        if context.is_valid and context.trace_id:
            return format(context.trace_id, "032x")
    except Exception:
        pass
    return None


def derived_trace_id(trace_id: str, session_id: str, turn_index: int) -> bool:
    """Whether this id was derived here rather than taken from a real span."""
    return trace_id == trace_id_for(session_id, turn_index)


class PolicyClient:
    """Reads the active policy and its live attestation state from the Policy Server.

    Holds the last good answer. Not as a cache for speed, the Policy Server has
    its own 60s cache for that, but so that an unreachable control plane degrades
    to `unknown` with the previous policy still enforcing, rather than to nothing.
    """

    def __init__(self, base_url: str, timeout: float = 5.0,
                 token_fn: Optional[Callable[[], Optional[str]]] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token_fn = token_fn
        self._last: Optional[dict] = None
        self._last_at: float = 0.0

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(self.base_url + path)
        if self.token_fn:
            token = self.token_fn()
            if token:
                req.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def active(self) -> dict:
        """The active policy plus its state, or the last good answer marked unknown."""
        try:
            answer = _normalise(self._get("/policy/active"))
            self._last = answer
            self._last_at = time.time()
            return answer
        except Exception as exc:  # network, 5xx, malformed body: all the same here
            if self._last is None:
                # Nothing has ever been fetched. There is no policy to enforce
                # and no last known state to fall back to. Say so; the caller
                # decides, and the caller's decision is to block.
                return {"version": None, "policy": None, "state": UNKNOWN,
                        "attested": False, "stale": True,
                        "detail": f"policy server unreachable: {type(exc).__name__}"}
            age = time.time() - self._last_at
            stale = _normalise(self._last)
            stale["state"] = UNKNOWN
            stale["attested"] = False
            stale["stale"] = True
            stale["detail"] = (f"policy server unreachable for {age:.0f}s: "
                               f"{type(exc).__name__}")
            if age > STALE_SECONDS:
                stale["expired"] = True
            return stale


SCREENING_FIELDS = ("ma_prompt_injection_score", "ma_jailbreak_score", "ma_verdict")
SCREENING_UNAVAILABLE = "SCREENING-UNAVAILABLE"
POLICY_EXPIRED = "POLICY-EXPIRED"

# Every verdict that means "this turn was not screened". A policy that keys on a
# screening field cannot be evaluated against any of them, and the difference
# between them belongs in the record, not in whether the call proceeds.
UNSCREENED = ("SCREENING_FAILED", "NOT_SCREENED")


def needs_screening(policy) -> bool:
    """Whether any rule in this policy cannot be evaluated without a screening.

    Asked of the policy rather than assumed, so a policy with no Model Armor
    predicate is unaffected by an Armor outage. Only the rules that actually
    depend on screening cause a call to be refused when it is missing.
    """
    for rule in getattr(policy, "rules", []):
        for predicate in getattr(rule, "all_of", []):
            if getattr(predicate, "field", None) in SCREENING_FIELDS:
                return True
    return False


def _normalise(answer: dict) -> dict:
    """Lower-case the state, once, at the boundary.

    The Policy Server reports ATTESTED and this module's constant is "attested",
    so `state == ATTESTED` was false for every response it ever sent. Every
    block was then recorded as unattested, including blocks under a perfectly
    good version, and the refusal read "policy state ATTESTED - cannot currently
    be justified from evidence". A distinction that is always false is not a
    distinction, and it is the one this whole system exists to draw.
    """
    out = dict(answer)
    state = out.get("state")
    if isinstance(state, str):
        out["state"] = state.lower()
    return out


class Enforcer:
    """Policy enforcement for one agent. Constructed once, called per tool call."""

    def __init__(self, agent_id: str, policy: PolicyClient,
                 armor: Optional[Callable[[str], dict]] = None,
                 sink: Optional[Callable[[dict], None]] = None,
                 denying_rule: Optional[Callable[[object, dict], Optional[str]]] = None):
        self.agent_id = agent_id
        self.policy = policy
        self.armor = armor
        self.sink = sink
        if denying_rule is None:
            from caseharden.interpreter import denying_rule as _dr
            denying_rule = _dr
        self._denying_rule = denying_rule

    def screen(self, text: Optional[str]) -> dict:
        """Model Armor verdict fields, or empty when screening is not configured.

        Empty is not "clean". The DSL distinguishes a missing field from a low
        score, so a policy that keys on an injection score simply does not match
        when screening did not run, rather than matching as though it passed.
        """
        if not self.armor:
            return {}
        if not text:
            # A turn with no text cannot be screened, which is not the same as a
            # turn that screened clean. Saying so explicitly matters: returning
            # {} here made an empty turn_text indistinguishable from a screened
            # turn in every downstream check, and an adversarial pass drove a
            # refund through by simply having no text to screen.
            return {"ma_verdict": "NOT_SCREENED",
                    "ma_error": "the turn carried no text to screen"}
        try:
            return self.armor(text)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"[:300]
            # Loud. A screening failure that only shows up as a null score in
            # the warehouse is indistinguishable from a clean turn six hours
            # later, and this one cost a deploy cycle to find.
            print(f"ALERT caseharden model armor screening failed: {detail}",
                  file=sys.stderr, flush=True)
            return {"ma_verdict": "SCREENING_FAILED", "ma_error": detail}

    def decide(self, event: dict) -> Decision:
        """Screen, evaluate, and record one tool call."""
        armor = self.screen(event.get("turn_text"))
        enriched = dict(event)
        for key in ("ma_prompt_injection_score", "ma_jailbreak_score", "ma_verdict"):
            if key in armor:
                enriched[key] = armor[key]

        answer = self.policy.active()
        version = answer.get("version")
        state = str(answer.get("state") or UNKNOWN).lower()
        raw_policy = answer.get("policy")
        trace = (event.get("trace_id") or current_trace_id()
                 or trace_id_for(event.get("session_id", ""), event.get("turn_index", 0)))

        if answer.get("expired"):
            # STALE_SECONDS has to bound something or it is decoration. Past it,
            # the last fetched policy is refused rather than enforced onward:
            # promotions only ever narrow, so an indefinitely old policy is a
            # permissive one, and permissive is the wrong direction to drift in
            # while the control plane is unreachable.
            decision = Decision(
                allowed=False, rule=POLICY_EXPIRED, policy_version=version,
                attestation_state=UNKNOWN, reason_attested=False, trace_id=trace,
                armor=armor, source="expired",
                detail=answer.get("detail", "policy older than the staleness bound"))
            self._record(enriched, decision)
            return decision

        if raw_policy is None:
            # No policy has ever been fetched. Nothing to enforce and nothing to
            # claim: refuse the call rather than pass it through unchecked.
            decision = Decision(
                allowed=False, rule="NO-POLICY", policy_version=None,
                attestation_state=UNKNOWN, reason_attested=False, trace_id=trace,
                armor=armor, source="degraded",
                detail=answer.get("detail", "no policy available"))
            self._record(enriched, decision)
            return decision

        policy = _as_policy(raw_policy)

        # A screening failure is not a clean turn. If the active policy has a
        # rule that keys on a Model Armor field and screening did not produce
        # one, that rule cannot be evaluated, and letting the call through
        # because the check was unavailable turns an Armor outage into a bypass
        # for the exact rule it was protecting. Deny, and say which.
        if armor.get("ma_verdict") in UNSCREENED and needs_screening(policy):
            decision = Decision(
                allowed=False, rule=SCREENING_UNAVAILABLE,
                policy_version=version, attestation_state=state,
                # Never justified: the record cannot show a screening that did
                # not happen.
                reason_attested=False, trace_id=trace, armor=armor,
                source="degraded",
                detail=armor.get("ma_error", "screening unavailable"))
            self._record(enriched, decision)
            return decision

        rule = self._denying_rule(policy, enriched)
        attested = bool(answer.get("attested")) and state == ATTESTED
        decision = Decision(
            allowed=rule is None,
            rule=rule,
            policy_version=version,
            attestation_state=state,
            # An allow makes no claim, so it carries no attestation. Only a block
            # asserts something the record has to be able to back.
            reason_attested=bool(rule) and attested,
            trace_id=trace,
            armor=armor,
            source="stale" if answer.get("stale") else "live",
            detail=answer.get("detail", ""))
        self._record(enriched, decision)
        return decision

    def _record(self, event: dict, decision: Decision) -> None:
        if not self.sink:
            return
        row = dict(event)
        row["agent_id"] = row.get("agent_id") or self.agent_id
        row["trace_id"] = decision.trace_id
        row["policy_version"] = decision.policy_version
        row["attestation_state"] = decision.attestation_state
        row["decision"] = "DENY" if not decision.allowed else "ALLOW"
        row["decision_rule"] = decision.rule
        row["decision_attested"] = decision.reason_attested
        for key in ("ma_prompt_injection_score", "ma_jailbreak_score", "ma_verdict"):
            row.setdefault(key, None)
        try:
            self.sink(row)
        except Exception:
            # A sink failure must not turn a block into an allow. The decision
            # is already made; losing the record is bad, losing the block is worse.
            pass


def _as_policy(raw):
    """Accept a parsed Policy, a dict, or a JSON string. The server sends a dict."""
    from caseharden.dsl import Policy, parse
    if isinstance(raw, Policy):
        return raw
    return parse(raw)
