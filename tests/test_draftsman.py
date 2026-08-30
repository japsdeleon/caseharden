#!/usr/bin/env python3
"""The Draftsman answers drafting questions from stored evidence, offline here.

Everything BigQuery is monkeypatched: `bq.access_token`, `bq.query` and
`bq.query_job` are replaced before any command runs, and the autouse fixture
makes an unpatched call fail loudly rather than reach the network. The overlap
verdicts are tested on the pure seam; the commands are tested through main().

run:  python3 -m pytest tests/test_draftsman.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from caseharden import bq, draftsman  # noqa: E402
from caseharden.dsl import canonical_json, parse  # noqa: E402

P_REFUND = {"op": "equals", "field": "tool_name", "value": "issue_refund"}
P_LARGE = {"op": "at_least", "field": "amount_cents", "value": 500000}
P_SCOPE = {"op": "outside_declared_scope"}


def rule(rid, *preds):
    return {"id": rid, "action": "deny", "reason": "test rule",
            "all_of": list(preds)}


def policy(version, *rules_):
    return parse({"version": version, "rules": list(rules_)})


def registry_rows():
    """Two rows the way `ChainStore.versions()` returns them: BOOLs as strings,
    a pre-lines row carrying policy_id None, the policy as a JSON string."""
    v5 = {"version": "v5", "rules": [rule("refund-and-large", P_REFUND, P_LARGE),
                                     rule("sleeper", P_SCOPE)]}
    v4 = {"version": "v4", "rules": [rule("old-rule", P_SCOPE)]}
    return [
        {"version": "v5", "active": "true", "policy_id": None,
         "policy": json.dumps(v5), "root": "r", "certificate_uri": ""},
        {"version": "v4", "active": "false", "policy_id": "conduct-policy",
         "policy": json.dumps(v4), "root": "", "certificate_uri": ""},
    ]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No test may reach the network. An unpatched call is a test bug."""
    def refuse(*a, **k):
        raise AssertionError("reached for BigQuery without a fake in place")
    monkeypatch.setattr(bq, "access_token", refuse)
    monkeypatch.setattr(bq, "query", refuse)
    monkeypatch.setattr(bq, "query_job", refuse)


# --------------------------------------------------------------------------
# overlap: the pure seam
# --------------------------------------------------------------------------

def test_overlap_duplicate():
    draft = policy("v2-pay", rule("dup-rule", P_REFUND, P_LARGE))
    active = [("payments-policy", "v1-pay",
               policy("v1-pay", rule("large-refund", P_REFUND, P_LARGE)))]
    report = draftsman.overlap_report(draft, active)
    assert len(report) == 1
    assert report[0].startswith(
        "dup-rule vs payments-policy/v1-pay/large-refund: DUPLICATE")


def test_overlap_covered_by_a_broader_active_rule():
    draft = policy("v2-pay", rule("narrow-rule", P_REFUND, P_LARGE))
    active = [("payments-policy", "v1-pay",
               policy("v1-pay", rule("any-refund", P_REFUND)))]
    report = draftsman.overlap_report(draft, active)
    assert len(report) == 1
    assert "narrow-rule vs payments-policy/v1-pay/any-refund: COVERED" in report[0]


def test_overlap_wider_than_an_active_rule():
    draft = policy("v2-pay", rule("wide-rule", P_REFUND))
    active = [("conduct-policy", "v5",
               policy("v5", rule("refund-and-large", P_REFUND, P_LARGE)))]
    report = draftsman.overlap_report(draft, active)
    assert len(report) == 1
    assert "wide-rule vs conduct-policy/v5/refund-and-large: WIDER" in report[0]


def test_overlap_reports_when_nothing_overlaps():
    draft = policy("v2-pay", rule("scope-rule", P_SCOPE))
    active = [("payments-policy", "v1-pay",
               policy("v1-pay", rule("any-refund", P_REFUND)))]
    report = draftsman.overlap_report(draft, active)
    assert report == ["no active rule overlaps any draft rule"]


def test_overlap_command_reads_the_registry_and_exits_zero(
        monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(bq, "access_token", lambda sa=None: "t")
    monkeypatch.setattr(bq, "query", lambda *a, **k: registry_rows())
    candidate = tmp_path / "cand.json"
    # scope-copy duplicates a predicate set that exists in BOTH the active v5
    # (sleeper) and the inactive v4 (old-rule). A dead active-filter would then
    # print old-rule as a partner — a mutation sweep found the earlier version
    # of this test asserting old-rule's absence on a draft that could never
    # have matched it, which proved nothing.
    candidate.write_text(json.dumps(
        {"version": "v2-pay", "rules": [rule("wide-refund", P_REFUND),
                                        rule("scope-copy", P_SCOPE)]}))
    rc = draftsman.main(["overlap", "--candidate", str(candidate)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "wide-refund vs conduct-policy/v5/refund-and-large: WIDER" in out
    assert "scope-copy vs conduct-policy/v5/sleeper: DUPLICATE" in out
    # v4 is inactive; its rule must not appear as an overlap partner even for
    # a draft rule that would otherwise pair with it.
    assert "old-rule" not in out


# --------------------------------------------------------------------------
# rot
# --------------------------------------------------------------------------

def test_rot_labels_earning_dormant_and_superseded(monkeypatch, capsys):
    identities = []
    monkeypatch.setattr(bq, "access_token",
                        lambda sa=None: identities.append(sa) or "t")
    monkeypatch.setattr(bq, "query", lambda *a, **k: registry_rows())
    captured = {}

    def fake_query_job(sql, project, token, params=None, **kw):
        captured["sql"], captured["params"] = sql, params
        return ([
            {"decision_rule": "refund-and-large", "policy_version": "v5",
             "denials": "7", "last_fired": "2026-08-28T10:00:00Z"},
            {"decision_rule": "ghost-rule", "policy_version": "v4",
             "denials": "3", "last_fired": "2026-08-01T00:00:00Z"},
        ], "europe-west3:job_rot_1")

    monkeypatch.setattr(bq, "query_job", fake_query_job)
    rc = draftsman.main(["rot", "--window-days", "30"])
    out = capsys.readouterr().out
    assert rc == 0
    assert identities == [
        "proposer-sa@devpost-hackathon-506416.iam.gserviceaccount.com"]
    assert captured["params"] == {"days": 30}
    assert "job_rot_1" in out
    assert "unique within a policy" in out

    earning = next(l for l in out.splitlines() if "refund-and-large" in l)
    assert "EARNING" in earning and "7" in earning
    assert "2026-08-28T10:00:00Z" in earning
    dormant = next(l for l in out.splitlines() if "sleeper" in l)
    assert "DORMANT" in dormant
    superseded = next(l for l in out.splitlines() if "ghost-rule" in l)
    assert "superseded" in superseded


# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------

def test_patterns_runs_three_windowed_queries(monkeypatch, capsys):
    monkeypatch.setattr(bq, "access_token", lambda sa=None: "t")
    calls = []

    def fake_query_job(sql, project, token, params=None, **kw):
        calls.append((sql, params))
        rows = {
            1: [{"tool_name": "issue_refund", "calls": "40", "denies": "5"}],
            2: [{"calls": "40", "top": "500000",
                 "quartiles": ["100", "900", "5000", "20000", "500000"]}],
            3: [{"session_id": "sess-9", "calls": "6", "cross_tenant": "true"}],
        }[len(calls)]
        return rows, f"europe-west3:job_pat_{len(calls)}"

    monkeypatch.setattr(bq, "query_job", fake_query_job)
    rc = draftsman.main(["patterns", "--use-case", "payments",
                         "--window-days", "7"])
    out = capsys.readouterr().out
    assert rc == 0
    assert len(calls) == 3
    assert all(p == {"days": 7} for _, p in calls)
    for n in (1, 2, 3):
        assert f"job_pat_{n}" in out
    assert "sess-9" in out and "CROSS-TENANT" in out
    assert "proposes nothing" in out


# --------------------------------------------------------------------------
# draft
# --------------------------------------------------------------------------

def test_draft_writes_a_canonical_file_with_provenance(
        monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(bq, "access_token", lambda sa=None: "t")
    monkeypatch.setattr(bq, "query", lambda *a, **k: registry_rows())
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps([rule("large-refund", P_REFUND, P_LARGE)]))
    out_path = tmp_path / "v2-pay.json"
    rc = draftsman.main(["draft", "--version", "v2-pay",
                         "--line", "payments-policy",
                         "--rules", str(rules_path), "--out", str(out_path)])
    out = capsys.readouterr().out
    assert rc == 0
    expected = canonical_json(policy("v2-pay",
                                     rule("large-refund", P_REFUND, P_LARGE)))
    assert out_path.read_text().strip() == expected
    assert "payments-policy" in out and "v2-pay" in out and "1" in out
    assert "gate" in out and "human" in out
    assert "next" in out and "--policy-id payments-policy" in out
    # The inline overlap report ran against the active registry.
    assert "large-refund vs conduct-policy/v5/refund-and-large: DUPLICATE" in out


def test_draft_accepts_a_full_policy_document(monkeypatch, tmp_path):
    monkeypatch.setattr(bq, "access_token", lambda sa=None: "t")
    monkeypatch.setattr(bq, "query", lambda *a, **k: [])
    doc_path = tmp_path / "doc.json"
    doc_path.write_text(json.dumps(
        {"version": "v9", "rules": [rule("any-refund", P_REFUND)]}))
    out_path = tmp_path / "v2-pay.json"
    rc = draftsman.main(["draft", "--version", "v2-pay",
                         "--line", "payments-policy",
                         "--rules", str(doc_path), "--out", str(out_path)])
    assert rc == 0
    # The --version flag names the candidate, not the document's own version.
    assert json.loads(out_path.read_text())["version"] == "v2-pay"


def test_draft_refuses_an_unknown_field_and_writes_nothing(tmp_path, capsys):
    # The offline fixture leaves every bq call refusing, which also proves the
    # candidate is validated before any registry read.
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps([
        {"id": "bad-rule", "action": "deny", "reason": "t",
         "all_of": [{"op": "equals", "field": "nonexistent_column",
                     "value": "x"}]}]))
    out_path = tmp_path / "bad.json"
    rc = draftsman.main(["draft", "--version", "v9",
                         "--line", "payments-policy",
                         "--rules", str(rules_path), "--out", str(out_path)])
    out = capsys.readouterr().out
    assert rc != 0
    assert not out_path.exists()
    assert "nonexistent_column" in out


# --------------------------------------------------------------------------
# narration
# --------------------------------------------------------------------------

def test_narrate_skips_when_the_library_is_absent(monkeypatch, capsys):
    monkeypatch.setattr(bq, "access_token", lambda sa=None: "t")
    monkeypatch.setattr(bq, "query", lambda *a, **k: registry_rows())
    monkeypatch.setattr(bq, "query_job",
                        lambda *a, **k: ([], "europe-west3:job_rot_2"))
    # None in sys.modules makes `from google import genai` raise ImportError
    # even on a machine where the library happens to be installed.
    monkeypatch.setitem(sys.modules, "google", None)
    rc = draftsman.main(["rot", "--window-days", "5", "--narrate"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("narration skipped") == 1
    assert "not installed" in out


# --------------------------------------------------------------------------
# the wall, enforced by the bench itself
# --------------------------------------------------------------------------

def test_the_bench_refuses_the_examiners_identity():
    with pytest.raises(SystemExit) as excinfo:
        draftsman.main(["--impersonate",
                        "examiner-sa@devpost-hackathon-506416.iam.gserviceaccount.com",
                        "rot", "--window-days", "7"])
    assert "sealed exam" in str(excinfo.value)


def test_patterns_refuses_exam_datasets(capsys):
    rc = draftsman.main(["patterns", "--use-case", "payments",
                         "--window-days", "7", "--dataset", "holdout_sealed"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "REFUSED" in out and "exam" in out


def test_patterns_on_the_training_corpus_asks_for_no_decision_column(
        monkeypatch, capsys):
    """conduct_train predates enforcement; a deny-share query there is a 400."""
    calls = []

    def fake(sql, project, token, params=None, **k):
        calls.append(sql)
        return [], f"job_{len(calls)}"
    monkeypatch.setattr(bq, "access_token", lambda sa=None: "t")
    monkeypatch.setattr(bq, "query_job", fake)
    rc = draftsman.main(["patterns", "--use-case", "payments",
                         "--window-days", "7", "--dataset", "conduct_train"])
    assert rc == 0
    assert "decision" not in calls[0]
    out = capsys.readouterr().out
    assert "deny share" not in out


def test_rot_attributes_shared_rule_ids_by_line(monkeypatch, capsys):
    """One line's denials must not read as another line's same-named rule
    earning its place — attribution goes through the enforcing version."""
    rows = [
        {"version": "v5", "active": "true", "policy_id": None,
         "policy": json.dumps({"version": "v5",
                               "rules": [rule("sleeper", P_SCOPE)]}),
         "root": "r", "certificate_uri": ""},
        {"version": "v1-pay", "active": "true", "policy_id": "payments-policy",
         "policy": json.dumps({"version": "v1-pay",
                               "rules": [rule("sleeper", P_REFUND)]}),
         "root": "", "certificate_uri": ""},
    ]
    monkeypatch.setattr(bq, "access_token", lambda sa=None: "t")
    monkeypatch.setattr(bq, "query", lambda *a, **k: rows)
    monkeypatch.setattr(bq, "query_job", lambda *a, **k: ([
        {"decision_rule": "sleeper", "policy_version": "v5", "denials": "9",
         "last_fired": "2026-08-28T10:00:00Z"}], "job_x"))
    rc = draftsman.main(["rot", "--window-days", "30"])
    out = capsys.readouterr().out
    assert rc == 0
    conduct = next(l for l in out.splitlines()
                   if l.strip().startswith("conduct-policy"))
    pay = next(l for l in out.splitlines()
               if l.strip().startswith("payments-policy"))
    assert "EARNING" in conduct and "9" in conduct
    assert "DORMANT" in pay
