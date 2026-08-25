#!/usr/bin/env python3
"""The attestation state machine, pinned offline.

The exit criterion for Day 3 is a sequence, not a feature: green, quarantine,
promotion refused, re-attest, green again. These tests are that sequence plus
the ways it must refuse to work.

Two of them are the ones the whole entry rests on:

  granting the Proposer read on the sealed exam quarantines the version, because
  the exam's access list is hashed into link 1

  re-attestation refuses to run over an edited record or a widened access list,
  because otherwise `reattest` is an undo button for the tamper it exists to
  survive

run:  python3 -m pytest tests -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "generator"))

from caseharden import chain, dsl, notary  # noqa: E402
from caseharden.certificate import render  # noqa: E402
from caseharden.chain import Link  # noqa: E402
from caseharden.examiner import gate, local_corpora, monotonic, score_local  # noqa: E402
from caseharden.interpreter import structurally_monotonic  # noqa: E402
from caseharden.notary import (  # noqa: E402
    ATTESTED,
    EVENT_WINDOW,
    EXAM_SCORE,
    HOLDOUT_ACCESS,
    LINK_HASH,
    NO_CHAIN,
    QUARANTINED,
    ROOT_MISMATCH,
    UNKNOWN,
    reattest,
    verify,
)

CORPORA = local_corpora()
ACTIVE = dsl.load(str(REPO / "policies" / "v3-active.json"))
GOOD = dsl.load(str(REPO / "policies" / "v4-candidate-b.json"))
OVER_BLOCKING = dsl.load(str(REPO / "policies" / "v4-candidate-a.json"))

DATASET = "conduct_train"
START, END = "2026-08-14T00:00:00Z", "2026-08-15T00:00:00Z"
CITED = [
    {"event_id": f"e_{i:05d}", "ts": "2026-08-14T09:00:00Z"} for i in range(5)
]
SEALED_ACCESS = [{"role": "OWNER", "userByEmail": "examiner-sa@p.iam.gserviceaccount.com"}]
PROPOSER_GRANT = {"role": "READER", "userByEmail": "proposer-sa@p.iam.gserviceaccount.com"}
SEALED_REACH = [{"role": "roles/bigquery.metadataViewer",
                 "members": ["serviceAccount:notary-sa@p.iam.gserviceaccount.com"]}]
PROJECT_GRANT = {"role": "roles/bigquery.dataViewer",
                 "members": ["serviceAccount:proposer-sa@p.iam.gserviceaccount.com"]}


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------

class FakeEvidence(chain.Evidence):
    """The warehouse as verification finds it, which is the whole variable here.

    Scores come from the real Python evaluator over the real seeded corpora, so
    an EXAM link that re-derives is re-deriving something.
    """

    def __init__(self, events=None, access=None, corpora=None, error=None, reach=None):
        self._events = CITED if events is None else events
        self._access = SEALED_ACCESS if access is None else access
        self._reach = SEALED_REACH if reach is None else reach
        self._corpora = corpora or CORPORA
        self._error = error

    def cited_events(self, dataset, start, end):
        if self._error:
            raise self._error
        return {e["event_id"]: chain.row_digest(e)
                for e in self._events if start <= e["ts"] < end}

    def access_list(self, dataset):
        if self._error:
            raise self._error
        return self._access

    def exam_reach(self):
        if self._error:
            raise self._error
        return self._reach

    def score(self, policy):
        if self._error:
            raise self._error
        return score_local(policy, self._corpora)

    def widened(self, candidate, current):
        _, count = monotonic(candidate, current,
                             self._corpora["benign_corpus"] + self._corpora["holdout_sealed"])
        return count


def stored(payload: dict) -> dict:
    """Round-trip through JSON, because that is what BigQuery hands back.

    Comparing a dict against itself proves nothing about a chain read from a
    table, where every value has been through a string.
    """
    return json.loads(json.dumps(payload))


def make_chain(version="v4", events=None, access=None, candidate=GOOD, current=ACTIVE,
               reach=None):
    evidence = FakeEvidence(events, access, reach=reach)
    cited = evidence.cited_events(DATASET, START, END)
    cand, curr = score_local(candidate, CORPORA), score_local(current, CORPORA)
    monotone, uncovered = structurally_monotonic(candidate, current)
    verdict = gate(cand, curr, monotone, uncovered, evidence.widened(candidate, current))
    assert verdict.passed, "the fixture chain must record a promotion that happened"
    return notary.bind_approval(chain.build(version, [
        ("EVIDENCE", stored(notary._evidence_payload(
            DATASET, START, END, cited, "holdout_sealed", access or SEALED_ACCESS,
            reach if reach is not None else SEALED_REACH))),
        ("FINDING", stored({"family": "scope-violation", "sessions": ["s_1", "s_2"]})),
        ("VERDICT", stored({"analyst": "a@example", "disposition": "confirmed abuse"})),
        ("DRAFT", stored({"version": candidate.version, "rule_count": len(candidate.rules)})),
        ("HOLDOUT-DENIED", stored({"principal": "proposer-sa@p", "dataset": "holdout_sealed",
                                   "permission": "bigquery.tables.getData", "http_code": 403})),
        ("EXAM", stored(notary._exam_payload(candidate, current, cand, curr, verdict))),
        ("APPROVAL", stored({"approver": "a@example", "verdict": verdict.reason,
                             "approves_exam_hash": None})),
    ]))


def certificate(links):
    return {"root": chain.root_of(links)}


# --------------------------------------------------------------------------
# Green
# --------------------------------------------------------------------------

def test_an_intact_chain_attests():
    links = make_chain()
    att = verify("v4", links, FakeEvidence(), certificate(links))
    assert att.state == ATTESTED
    assert att.promotions == "OPEN"
    assert att.break_code is None


def test_the_evidence_and_the_exam_are_re_derived_and_the_rest_is_not():
    """The README claims re-derivation for two link kinds. It is two, not seven."""
    links = make_chain()
    att = verify("v4", links, FakeEvidence(), certificate(links))
    derived = {r.kind for r in att.results if r.mode == "re-derived"}
    assert derived == {"EVIDENCE", "EXAM"}
    assert {r.kind for r in att.results if r.mode == "recorded"} == {
        "FINDING", "VERDICT", "DRAFT", "HOLDOUT-DENIED", "APPROVAL"}


# --------------------------------------------------------------------------
# The chain itself
# --------------------------------------------------------------------------

def test_an_edited_payload_breaks_at_the_link_that_carries_it():
    links = make_chain()
    links[2].payload["disposition"] = "no action"
    att = verify("v4", links, FakeEvidence(), certificate(links))
    assert att.state == QUARANTINED
    assert (att.break_code, att.break_seq) == (LINK_HASH, 3)


def test_a_link_cut_out_of_the_middle_is_caught():
    """Deleting a link leaves the next one pointing at a hash that is now absent."""
    links = make_chain()
    del links[3]
    att = verify("v4", links, FakeEvidence(), certificate(links))
    assert att.break_code == LINK_HASH


def test_a_re_hashed_chain_still_fails_against_its_sealed_root():
    """The tamper that repairs its own hashes, which is why the root is sealed.

    An attacker with write access to the chain table can edit a payload and
    recompute every hash after it, including re-pointing the approval at the
    exam's new hash. The chain then walks clean and satisfies its own grammar.
    What it cannot do is change the certificate already written to the
    retention-locked bucket.
    """
    links = make_chain()
    sealed = certificate(links)
    edited = list(links)
    edited[2] = Link("v4", 3, "VERDICT", {"analyst": "a@example", "disposition": "no action"},
                     edited[1].hash)
    prev = edited[2].hash
    for i in range(3, len(edited)):
        edited[i] = Link("v4", edited[i].seq, edited[i].kind, edited[i].payload, prev)
        prev = edited[i].hash
    edited = notary.bind_approval(edited)
    assert notary._walk_hashes(edited) is None, "the re-hashed chain is internally consistent"
    assert notary._required_shape(edited) is None
    att = verify("v4", edited, FakeEvidence(), sealed)
    assert (att.state, att.break_code) == (QUARANTINED, ROOT_MISMATCH)


def test_a_version_with_no_chain_is_not_attested():
    att = verify("v9", [], FakeEvidence(), None)
    assert (att.state, att.break_code, att.promotions) == (QUARANTINED, NO_CHAIN, "FROZEN")


# --------------------------------------------------------------------------
# The evidence
# --------------------------------------------------------------------------

def test_rewriting_a_cited_event_quarantines_and_names_it():
    """The row keeps its id and changes what it says the agent did.

    Digesting the ids alone caught an insert and a delete and nothing else. An
    adversarial pass rewrote a cited call to `issue_refund` against another
    tenant, kept the event id, and verification stayed green.
    """
    links = make_chain()
    rewritten = [dict(CITED[0], tool_name="issue_refund", tenant_id="t_999")] + CITED[1:]
    att = verify("v4", links, FakeEvidence(events=rewritten), certificate(links))
    assert (att.state, att.break_code) == (QUARANTINED, EVENT_WINDOW)
    assert "no longer match the row that was cited" in att.break_detail
    assert CITED[0]["event_id"] in att.break_detail


def test_a_late_arriving_event_quarantines_and_names_it():
    """The demo's break beat. One row of ordinary data, no attack."""
    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    att = verify("v4", links, FakeEvidence(events=later), certificate(links))
    assert (att.state, att.break_code, att.break_seq) == (QUARANTINED, EVENT_WINDOW, 1)
    assert "e_88214" in att.break_detail
    assert att.promotions == "FROZEN"


def test_an_event_outside_the_cited_window_changes_nothing():
    """Partition pruning is the budget claim; it is also the correctness claim."""
    links = make_chain()
    elsewhere = CITED + [{"event_id": "e_99999", "ts": "2026-08-16T00:00:01Z"}]
    att = verify("v4", links, FakeEvidence(events=elsewhere), certificate(links))
    assert att.state == ATTESTED


def test_a_deleted_conduct_event_quarantines_too():
    links = make_chain()
    att = verify("v4", links, FakeEvidence(events=CITED[:-1]), certificate(links))
    assert att.break_code == EVENT_WINDOW
    assert "gone" in att.break_detail


def test_granting_the_proposer_the_exam_quarantines_the_version():
    """The substitute for the IAM deny policy this project cannot create.

    A deny rule would beat a later grant. Without one, the guarantee is that a
    later grant cannot go unnoticed: the exam's access list is hashed into link
    1, so adding a reader breaks the chain.
    """
    links = make_chain()
    widened = SEALED_ACCESS + [PROPOSER_GRANT]
    att = verify("v4", links, FakeEvidence(access=widened), certificate(links))
    assert (att.state, att.break_code, att.break_seq) == (QUARANTINED, HOLDOUT_ACCESS, 1)
    assert "proposer-sa@p.iam.gserviceaccount.com" in att.break_detail
    assert "granted since promotion" in att.break_detail


def test_revoking_the_examiner_quarantines_as_well():
    links = make_chain()
    att = verify("v4", links, FakeEvidence(access=[]), certificate(links))
    assert att.break_code == HOLDOUT_ACCESS
    assert "revoked since promotion" in att.break_detail


def test_the_access_digest_does_not_depend_on_the_order_the_api_returns():
    entries = SEALED_ACCESS + [PROPOSER_GRANT]
    assert chain.digest_access(entries) == chain.digest_access(list(reversed(entries)))


# --------------------------------------------------------------------------
# The exam
# --------------------------------------------------------------------------

def test_a_changed_holdout_quarantines_at_the_exam_link():
    """The Examiner is re-run, not trusted. Its answer moving is a break."""
    links = make_chain()
    corpora = dict(CORPORA, holdout_sealed=CORPORA["holdout_sealed"][:200])
    att = verify("v4", links, FakeEvidence(corpora=corpora), certificate(links))
    assert (att.state, att.break_code, att.break_seq) == (QUARANTINED, EXAM_SCORE, 6)


def test_the_exam_break_names_the_measurement_that_moved():
    links = make_chain()
    corpora = dict(CORPORA, holdout_sealed=CORPORA["holdout_sealed"][:200])
    att = verify("v4", links, FakeEvidence(corpora=corpora), certificate(links))
    assert "the Examiner measured" in att.break_detail


# --------------------------------------------------------------------------
# unknown, which must never be attested
# --------------------------------------------------------------------------

def test_a_backend_failure_is_unknown_and_freezes_promotion():
    """A verify that cannot run is not a verify that passed.

    This is the same shape as the Day 2 finding where a timed-out BigQuery job
    read as a clean benign score.
    """
    att = verify("v4", make_chain(), FakeEvidence(error=RuntimeError("BigQuery is down")), None)
    assert (att.state, att.attested, att.promotions) == (UNKNOWN, False, "FROZEN")
    assert "BigQuery is down" in att.break_detail


# --------------------------------------------------------------------------
# reattest
# --------------------------------------------------------------------------

def test_reattest_refuses_to_launder_an_edited_record():
    """Otherwise reattest is an undo button for the tamper it exists to survive."""
    links = make_chain()
    links[2].payload["disposition"] = "no action"
    before, link, message = reattest("v4", links, FakeEvidence(), certificate(links))
    assert link is None
    assert before.break_code == LINK_HASH
    assert message.startswith("REFUSED")
    assert "does not launder an edit" in message


def test_reattest_refuses_a_widened_exam_access_list():
    """Re-deriving over a grant to the Proposer would record it as justified."""
    links = make_chain()
    widened = SEALED_ACCESS + [PROPOSER_GRANT]
    before, link, message = reattest("v4", links, FakeEvidence(access=widened),
                                     certificate(links))
    assert link is None
    assert message.startswith("REFUSED")
    assert "Revoke the grant" in message


def test_reattest_over_a_late_event_appends_evidence_changed_and_goes_green():
    """The remedy beat: the record is not edited, it is superseded."""
    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    evidence = FakeEvidence(events=later)
    before, link, message = reattest("v4", links, evidence, certificate(links))
    assert before.state == QUARANTINED
    assert link is not None and link.kind == "EVIDENCE-CHANGED" and link.seq == 8
    assert message.startswith("RE-ATTESTED")

    extended = links + [link]
    after = verify("v4", extended, evidence, certificate(extended))
    assert after.state == ATTESTED
    assert after.promotions == "OPEN"


def test_the_superseded_evidence_link_is_still_in_the_chain_and_says_so():
    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    evidence = FakeEvidence(events=later)
    _, link, _ = reattest("v4", links, evidence, certificate(links))
    extended = links + [link]
    att = verify("v4", extended, evidence, certificate(extended))
    first = next(r for r in att.results if r.seq == 1)
    assert first.status == "SUPERSEDED"
    assert "link 8" in first.detail
    assert extended[0].payload["event_digest"] != link.payload["event_digest"]
    assert link.payload["supersedes"] == 1
    assert notary.EVENT_WINDOW in link.payload["reason"]


def test_reattest_refuses_when_the_gate_no_longer_passes():
    """Evidence can move in a direction that unmakes the promotion.

    Here the holdout is cut down until the candidate no longer beats the active
    version on sealed attacks. The version stays quarantined and keeps enforcing.
    """
    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    corpora = dict(CORPORA, holdout_sealed=[
        e for e in CORPORA["holdout_sealed"] if e["label"] in (None, "benign")])
    before, link, message = reattest(
        "v4", links, FakeEvidence(events=later, corpora=corpora), certificate(links))
    assert link is None
    assert message.startswith("REFUSED")
    assert "the gate no longer passes" in message
    assert "keeps enforcing" in message


def test_reattest_on_an_attested_version_writes_nothing():
    links = make_chain()
    before, link, message = reattest("v4", links, FakeEvidence(), certificate(links))
    assert (link, before.state) == (None, ATTESTED)
    assert "Nothing to re-derive" in message


# --------------------------------------------------------------------------
# The promotion freeze and the viewer
# --------------------------------------------------------------------------

def test_every_non_green_state_freezes_promotion():
    """The freeze is one property of the state, so it is asserted over all of them."""
    links = make_chain()
    cases = {
        "late event": FakeEvidence(events=CITED + [{"event_id": "e_x", "ts": START}]),
        "granted access": FakeEvidence(access=SEALED_ACCESS + [PROPOSER_GRANT]),
        "backend down": FakeEvidence(error=RuntimeError("down")),
    }
    for name, evidence in cases.items():
        att = verify("v4", links, evidence, certificate(links))
        assert att.attested is False, name
        assert att.promotions == "FROZEN", name


def test_the_certificate_page_shows_the_break_and_names_the_event():
    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    att = verify("v4", links, FakeEvidence(events=later), certificate(links))
    page = render(att, links)
    assert "e_88214" in page
    assert "QUARANTINED" in page
    assert "EVENT-WINDOW" in page


def test_the_certificate_page_escapes_what_it_renders():
    """Link payloads carry model output and BigQuery error text.

    The hostile string is put in at build time. Mutating the payload afterwards
    breaks the link hash, which makes verify skip every later link and renders an
    empty detail, so the test would pass without escaping anything.
    """
    links = make_chain()
    links[1] = Link("v4", 2, "FINDING",
                    stored({"family": "<script>alert(1)</script>", "sessions": []}),
                    links[0].hash)
    for i in range(2, len(links)):
        links[i] = Link("v4", links[i].seq, links[i].kind, links[i].payload,
                        links[i - 1].hash)
    links = notary.bind_approval(links)
    att = verify("v4", links, FakeEvidence(), certificate(links))
    assert att.state == ATTESTED, "the hostile payload must reach the renderer"
    page = render(att, links)
    assert "<script>alert(1)</script>" not in page
    # Absence alone passes for a renderer that returns nothing at all, which is
    # how this test read before an adversarial pass replaced render with a stub.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.startswith("<!doctype html>")
    assert "conduct-policy@v4" in page


# --------------------------------------------------------------------------
# The Policy Server
# --------------------------------------------------------------------------

def test_the_policy_server_reports_unknown_when_it_cannot_verify(monkeypatch):
    from caseharden import bq as bq_module
    from caseharden.policy_server import Attestations

    def refuse(*_a, **_k):
        raise RuntimeError("no credentials")

    monkeypatch.setattr(bq_module, "access_token", refuse)
    state = Attestations("devpost-hackathon-506416").get("v4")
    assert state["attested"] is False
    assert state["state"] == "UNKNOWN"
    assert state["promotions"] == "FROZEN"


def test_the_policy_server_says_when_an_answer_came_from_cache():
    from caseharden.policy_server import Attestations

    calls = []

    class Counting(Attestations):
        def _fresh(self, version):
            calls.append(version)
            return {"version": version, "attested": True, "state": "ATTESTED",
                    "promotions": "OPEN"}

    server = Counting("devpost-hackathon-506416", ttl=60)
    first, second = server.get("v4"), server.get("v4")
    assert len(calls) == 1
    assert first["cached"] is False and second["cached"] is True
    assert "checked_s_ago" in second


def test_the_policy_server_cache_expires():
    from caseharden.policy_server import Attestations

    calls = []

    class Counting(Attestations):
        def _fresh(self, version):
            calls.append(version)
            return {"version": version, "attested": True, "state": "ATTESTED"}

    server = Counting("devpost-hackathon-506416", ttl=0)
    server.get("v4")
    server.get("v4")
    assert len(calls) == 2


# --------------------------------------------------------------------------
# What the chain is checked against
# --------------------------------------------------------------------------

def test_a_chain_with_no_sealed_certificate_is_not_attested():
    """Without a sealed root there is nothing the chain is checked against.

    A hash chain proves its own internal consistency and nothing else. Dropping
    its last link leaves a chain that walks clean, so the certificate in the
    locked bucket is not decoration, it is the anchor.
    """
    links = make_chain()
    att = verify("v4", links, FakeEvidence(), None)
    assert (att.state, att.break_code) == (QUARANTINED, notary.NO_CERTIFICATE)
    assert att.promotions == "FROZEN"


def test_dropping_the_approval_is_caught_by_the_grammar():
    links = make_chain()
    truncated = links[:-1]
    assert notary._walk_hashes(truncated) is None, "a truncated chain is self-consistent"
    att = verify("v4", truncated, FakeEvidence(), certificate(truncated))
    assert (att.state, att.break_code) == (QUARANTINED, notary.CHAIN_SHAPE)
    assert "no APPROVAL link" in att.break_detail


def test_dropping_a_trailing_link_the_grammar_allows_is_caught_by_the_root():
    """A chain can be truncated to something that is still a valid promotion.

    Cutting the last link off an eight-link chain leaves the original seven,
    which parse as a promotion, walk clean, and re-derive. Only the sealed root
    disagrees, which is the whole reason the root is sealed.
    """
    links = make_chain()
    full = links + [Link("v4", 8, "VERDICT", stored({"analyst": "b@example",
                                                     "disposition": "reviewed again"}),
                         links[-1].hash)]
    sealed = certificate(full)
    assert notary._walk_hashes(links) is None
    assert notary._required_shape(links) is None
    att = verify("v4", links, FakeEvidence(), sealed)
    assert (att.state, att.break_code) == (QUARANTINED, ROOT_MISMATCH)


def test_a_chain_that_is_not_a_promotion_is_not_attested():
    """One fabricated link with a matching sealed root used to attest.

    A hash chain proves its links are consecutive. It does not prove they say
    anything, so the grammar is required: evidence first, an exam, an approval.
    """
    fabricated = chain.build("v4", [("FINDING", {"family": "fabricated"})])
    att = verify("v4", fabricated, FakeEvidence(), certificate(fabricated))
    assert (att.state, att.break_code) == (QUARANTINED, notary.CHAIN_SHAPE)
    assert att.promotions == "FROZEN"


def test_a_chain_that_does_not_begin_with_evidence_is_not_attested():
    steps = [("FINDING", {"family": "x"}), ("EXAM", {}), ("APPROVAL", {})]
    links = chain.build("v4", steps)
    att = verify("v4", links, FakeEvidence(), certificate(links))
    assert att.break_code == notary.CHAIN_SHAPE
    assert "begins with EVIDENCE" in att.break_detail


def test_a_chain_with_no_exam_is_not_attested():
    links = make_chain()
    without_exam = chain.build("v4", [
        (l.kind, l.payload) for l in links if l.kind != "EXAM"])
    att = verify("v4", without_exam, FakeEvidence(), certificate(without_exam))
    assert att.break_code == notary.CHAIN_SHAPE
    assert "no EXAM link" in att.break_detail


def test_reattest_will_not_repair_a_missing_certificate():
    links = make_chain()
    _, link, message = reattest("v4", links, FakeEvidence(), None)
    assert link is None
    assert message.startswith("REFUSED")


def test_a_version_name_cannot_forge_a_link_hash():
    """The hash input is newline-joined, and only `version` comes from a flag.

    Everything else is drawn from a closed set or is JSON, which escapes its own
    newlines. A version carrying newlines could otherwise produce the same hash
    input as a different link.
    """
    with pytest.raises(ValueError):
        chain.link_hash("v4\n2\nFINDING\n", 1, "EVIDENCE", None, {})
    with pytest.raises(ValueError):
        chain.build("v4\n9\nAPPROVAL", [("EVIDENCE", {})])
    assert chain.link_hash("v4", 1, "EVIDENCE", None, {})


def test_two_access_entries_with_no_member_do_not_collide():
    """An authorized-view entry carries no member at all.

    Reducing every such entry to the same string would leave the digest blind to
    swapping one authorized view for another.
    """
    a = [{"role": "READER", "view": {"datasetId": "d", "tableId": "one"}}]
    b = [{"role": "READER", "view": {"datasetId": "d", "tableId": "two"}}]
    assert chain.digest_access(a) != chain.digest_access(b)


def test_a_slow_verification_cannot_overwrite_a_newer_one():
    """Two refreshes overlap and the slower one finishes last.

    Ordered by finish time, a stale ATTESTED result replaces a QUARANTINED one
    and reopens promotions for another cache window. Cache entries are ordered by
    when their verification started instead.
    """
    import threading

    from caseharden.policy_server import Attestations

    started, release = threading.Event(), threading.Event()

    class Racing(Attestations):
        def _fresh(self, version):
            if not started.is_set():
                started.set()
                release.wait(5)
                return {"version": version, "attested": True, "state": "ATTESTED",
                        "promotions": "OPEN"}
            return {"version": version, "attested": False, "state": "QUARANTINED",
                    "promotions": "FROZEN"}

    server = Racing("devpost-hackathon-506416", ttl=60)
    slow = threading.Thread(target=lambda: server.get("v4"))
    slow.start()
    started.wait(5)
    assert server.get("v4")["state"] == "QUARANTINED"
    release.set()
    slow.join(5)
    after = server.get("v4")
    assert after["state"] == "QUARANTINED"
    assert after["promotions"] == "FROZEN"


def test_reattest_over_a_moved_exam_records_the_new_measurement():
    """The exam can move without unmaking the promotion.

    Extra benign sessions land in the holdout. The Examiner's numbers change, so
    the EXAM link no longer re-derives, but the candidate still beats the active
    version on every attack family and still denies nothing legitimate. The
    remedy is the same: record the new measurement, supersede the old one.
    """
    links = make_chain()
    benign_rows = [e for e in CORPORA["holdout_sealed"] if e["label"] == "benign"][:40]
    extra = [dict(e, event_id=f"x_{i}", session_id=f"s_extra_{i}")
             for i, e in enumerate(benign_rows)]
    assert extra, "the fixture needs benign holdout rows to duplicate"
    corpora = dict(CORPORA, holdout_sealed=CORPORA["holdout_sealed"] + extra)
    evidence = FakeEvidence(corpora=corpora)

    before = verify("v4", links, evidence, certificate(links))
    assert (before.state, before.break_code) == (QUARANTINED, EXAM_SCORE)

    _, link, message = reattest("v4", links, evidence, certificate(links))
    assert link is not None and link.kind == "EVIDENCE-CHANGED"
    assert message.startswith("RE-ATTESTED")
    extended = links + [link]
    assert verify("v4", extended, evidence, certificate(extended)).state == ATTESTED


def test_a_malformed_payload_quarantines_instead_of_raising():
    """Reaching this needs write access to the chain table.

    Editing a payload in place breaks the hash walk, so a malformed payload can
    only arrive as a hand-written link. It is still a record that does not say
    what its kind has to say, so it quarantines and names the link rather than
    raising out of verify.
    """
    links = make_chain()
    broken = chain.build("v4", [
        (l.kind, {"family": "not an exam"} if l.kind == "EXAM" else l.payload)
        for l in links])
    att = verify("v4", broken, FakeEvidence(), certificate(broken))
    assert (att.state, att.break_code, att.break_seq) == (QUARANTINED, notary.CHAIN_SHAPE, 6)
    assert "malformed" in att.break_detail


def test_an_exam_link_naming_a_policy_that_does_not_parse_quarantines():
    links = make_chain()
    exam = dict(links[5].payload)
    exam["candidate"] = {"version": "v4", "rules": [
        {"id": "r", "action": "allow", "reason": "x", "all_of": []}]}
    broken = chain.build("v4", [
        (l.kind, exam if l.kind == "EXAM" else l.payload) for l in links])
    att = verify("v4", broken, FakeEvidence(), certificate(broken))
    assert (att.state, att.break_code) == (QUARANTINED, notary.CHAIN_SHAPE)


# --------------------------------------------------------------------------
# What re-attestation leaves checkable afterwards
# --------------------------------------------------------------------------

def test_the_exam_is_still_re_derived_after_a_re_attestation():
    """The remedy must not switch the central claim off.

    Re-deriving only the evidence half of an EVIDENCE-CHANGED link left the exam
    unchecked from the first re-attestation onward: verify reported ATTESTED
    while the Examiner's own numbers had moved. Every version's exam is
    re-derived at every verify, whichever link states it.
    """
    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    _, extra, _ = reattest("v4", links, FakeEvidence(events=later), certificate(links))
    extended = links + [extra]

    fresh = FakeEvidence(events=later)
    att = verify("v4", extended, fresh, certificate(extended))
    assert att.state == ATTESTED
    assert {r.kind for r in att.results if r.mode == "re-derived"} == {"EVIDENCE-CHANGED"}
    assert "the Examiner re-scores" in next(r for r in att.results if r.seq == 8).detail

    # Now move the exam a second time, after the re-attestation.
    corpora = dict(CORPORA, holdout_sealed=CORPORA["holdout_sealed"][:200])
    moved = FakeEvidence(events=later, corpora=corpora)
    after = verify("v4", extended, moved, certificate(extended))
    assert (after.state, after.break_code, after.break_seq) == (QUARANTINED, EXAM_SCORE, 8)


def test_the_approval_must_name_the_exam_it_approved():
    """Otherwise the approval is a signature on nothing in particular."""
    links = make_chain()
    broken = chain.build("v4", [
        (l.kind, dict(l.payload, approves_exam_hash="0" * 64)
         if l.kind == "APPROVAL" else l.payload) for l in links])
    att = verify("v4", broken, FakeEvidence(), certificate(broken))
    assert (att.state, att.break_code, att.break_seq) == (QUARANTINED, notary.CHAIN_SHAPE, 7)
    assert "not a link in this chain" in att.break_detail


def test_a_project_level_grant_on_the_exam_quarantines():
    """A dataset access list is not the only way to reach a table.

    A project-level IAM binding grants the same permission and never appears in
    the dataset's ACL. Hashing the ACL alone left the easier of the two grants
    unnoticed, which is the exact route this project already uses to give the
    Notary metadata access without appearing in the exam's one-entry list.
    """
    links = make_chain()
    widened = SEALED_REACH + [PROJECT_GRANT]
    att = verify("v4", links, FakeEvidence(reach=widened), certificate(links))
    assert (att.state, att.break_code, att.break_seq) == (QUARANTINED, HOLDOUT_ACCESS, 1)
    assert "roles/bigquery.dataViewer" in att.break_detail
    assert "proposer-sa" in att.break_detail


def test_reattest_refuses_a_widened_project_level_grant():
    links = make_chain()
    widened = SEALED_REACH + [PROJECT_GRANT]
    _, link, message = reattest("v4", links, FakeEvidence(reach=widened), certificate(links))
    assert link is None
    assert message.startswith("REFUSED")
    assert "Revoke the grant" in message


def test_an_unrelated_project_role_does_not_quarantine():
    """Ordinary IAM churn must not withdraw a version's authority.

    Only roles that could carry bigquery.tables.getData are hashed: every
    predefined BigQuery role, and every custom role, whose permissions are not
    knowable from its name.
    """
    links = make_chain()
    unrelated = SEALED_REACH + [{"role": "roles/logging.viewer",
                                 "members": ["user:someone@example.com"]}]
    att = verify("v4", links, FakeEvidence(reach=unrelated), certificate(links))
    assert att.state == ATTESTED


def test_a_custom_role_is_hashed_because_its_permissions_are_not_in_its_name():
    links = make_chain()
    custom = SEALED_REACH + [{"role": "projects/p/roles/looksHarmless",
                              "members": ["serviceAccount:proposer-sa@p.iam.gserviceaccount.com"]}]
    att = verify("v4", links, FakeEvidence(reach=custom), certificate(links))
    assert (att.state, att.break_code) == (QUARANTINED, HOLDOUT_ACCESS)
    assert "looksHarmless" in att.break_detail


def test_the_break_carries_the_offending_event_as_its_own_field():
    """So a caller acts on the id instead of parsing prose for it."""
    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    att = verify("v4", links, FakeEvidence(events=later), certificate(links)).as_dict()
    assert att["event"] == "e_88214"
    assert att["break"] == "link 1 EVENT-WINDOW"


# --------------------------------------------------------------------------
# The freeze, at the point that actually writes a chain
# --------------------------------------------------------------------------

class FakeStore:
    """Just the two reads `parent_basis` makes."""

    def __init__(self, chains=None, rows=None):
        self._chains = chains or {}
        self._rows = rows or []

    def read(self, version):
        return self._chains.get(version, [])

    def versions(self):
        return self._rows


def test_a_promotion_onto_a_quarantined_parent_is_refused_at_the_source():
    """`promote` was a pre-check that wrote nothing and that nothing forced.

    `seed` is what writes a chain and marks a version active, so the freeze has
    to hold there. Both call this.
    """
    links = make_chain()
    store = FakeStore({"v4": links},
                      [{"version": "v4", "certificate_uri": "", "policy": "{}"}])
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    basis, attestation = notary.parent_basis(store, FakeEvidence(events=later), "v4", None)
    assert basis is None
    assert attestation.break_code == EVENT_WINDOW


def test_a_promotion_onto_an_attested_parent_is_allowed():
    links = make_chain()
    store = FakeStore({"v4": links}, [{"version": "v4", "certificate_uri": "", "policy": "{}"}])

    def sealed(_store, _version, _sa=None):
        return certificate(links)

    original, notary._sealed_for = notary._sealed_for, sealed
    try:
        basis, _ = notary.parent_basis(store, FakeEvidence(), "v4", None)
    finally:
        notary._sealed_for = original
    assert basis and "attested at root" in basis


def test_a_parent_that_was_never_a_version_is_refused():
    """`--parent v99` used to be accepted as a genesis version."""
    basis, attestation = notary.parent_basis(FakeStore(), FakeEvidence(), "v99", None)
    assert basis is None and attestation is None


def test_a_registered_genesis_parent_is_accepted():
    store = FakeStore(rows=[{"version": "v3", "root": "", "certificate_uri": "",
                             "policy": "{}"}])
    basis, _ = notary.parent_basis(store, FakeEvidence(), "v3", None)
    assert basis and "genesis" in basis


# --------------------------------------------------------------------------
# What the Policy Server serves
# --------------------------------------------------------------------------

def test_the_served_policy_comes_from_the_chain_not_the_registry():
    """The attested artifact and the enforced artifact have to be one object."""
    from caseharden.policy_server import _attested_policy

    links = make_chain()
    served = _attested_policy(links)
    assert served == links[5].payload["candidate"]
    assert served["version"] == GOOD.version


def test_the_served_policy_follows_a_re_attestation():
    from caseharden.policy_server import _attested_policy

    links = make_chain()
    later = CITED + [{"event_id": "e_88214", "ts": "2026-08-14T23:59:00Z"}]
    _, extra, _ = reattest("v4", links, FakeEvidence(events=later), certificate(links))
    assert _attested_policy(links + [extra]) == extra.payload["exam"]["candidate"]


def test_unknown_retains_the_last_state_that_was_established():
    """Section 3 defines `unknown` as last known state retained."""
    from caseharden import bq as bq_module
    from caseharden.policy_server import Attestations

    class Fixed(Attestations):
        def __init__(self):
            super().__init__("devpost-hackathon-506416", ttl=0)
            self.fail = False

        def _fresh(self, version):
            if self.fail:
                return Attestations._fresh(self, version)
            with self._lock:
                self._last_known[version] = {"state": "ATTESTED", "root": "abc"}
            return {"version": version, "attested": True, "state": "ATTESTED",
                    "promotions": "OPEN"}

    server = Fixed()
    assert server.get("v4")["state"] == "ATTESTED"

    server.fail = True
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(bq_module, "access_token",
                            lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("down")))
        unknown = server.get("v4")
    assert unknown["state"] == "UNKNOWN"
    assert unknown["attested"] is False and unknown["promotions"] == "FROZEN"
    assert unknown["last_known"] == {"state": "ATTESTED", "root": "abc"}


def test_the_server_freezes_when_the_registry_and_the_chain_disagree():
    """The attested artifact and the enforced artifact have to be one object.

    `policy.versions` is a table the Notary can write. Serving its copy without
    comparing it to the chain left the fleet enforcing a document nothing had
    attested to.
    """
    from caseharden import bq as bq_module
    from caseharden import chain as chain_module
    from caseharden import policy_server
    from caseharden.policy_server import Attestations

    links = make_chain()

    class Store:
        def __init__(self, *_a, **_k):
            pass

        def read(self, version):
            return links

        def versions(self):
            return [{"version": "v4", "certificate_uri": "gs://x/y.json",
                     "policy": json.dumps(other)}]

    def evidence(*_a, **_k):
        return FakeEvidence()

    other = {"version": "v4", "parent": None, "rules": []}

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(bq_module, "access_token", lambda *_a, **_k: "token")
        monkeypatch.setattr(chain_module, "BigQueryEvidence", evidence)
        # ChainStore is imported by name into policy_server, so patching it on
        # the chain module would not be seen there.
        monkeypatch.setattr(policy_server, "ChainStore", Store)
        monkeypatch.setattr(chain_module, "sealed_root",
                            lambda *_a, **_k: certificate(links))
        server = Attestations("devpost-hackathon-506416", ttl=0)
        mismatch = server.get("v4")

        other = json.loads(json.dumps(links[5].payload["candidate"]))
        agrees = server.get("v4")

    assert mismatch["registry_agrees"] is False
    assert mismatch["attested"] is False and mismatch["promotions"] == "FROZEN"
    assert mismatch["state"] == "ATTESTED", "the chain itself is intact; the registry is not"
    assert "registry_mismatch" in mismatch

    assert agrees["registry_agrees"] is True
    assert agrees["attested"] is True and agrees["promotions"] == "OPEN"
    assert agrees["policy"] == links[5].payload["candidate"]
