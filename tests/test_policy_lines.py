#!/usr/bin/env python3
"""A second policy line must not be able to touch the first one.

THREATS.md entry 11: the registry and the serving layer are line-aware and
nothing else is. What these tests pin is the boundary itself — registering or
promoting in one line deactivates nothing in another, a version name can never
be claimed twice, a parent from another line is nothing to build on, and a
registry row written before `policy_id` existed behaves as `conduct-policy`
everywhere.

run:  python3 -m pytest tests/test_policy_lines.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from caseharden import chain, notary  # noqa: E402
from caseharden.policy_server import parse_policy_path  # noqa: E402


class RecordingStore(chain.ChainStore):
    """Only the SQL is under test; no project, no token, no network."""

    def __init__(self):
        pass

    @property
    def project(self):
        return "devpost-hackathon-506416"

    @property
    def token(self):
        return "unused"


def recorded(monkeypatch, rows_by_marker=None):
    """Capture every statement `register` issues; answer reads from a table."""
    statements = []

    def fake_query(sql, project, token, params=None):
        statements.append((sql, params or {}))
        for marker, rows in (rows_by_marker or {}).items():
            if marker in sql:
                return rows
        return []

    monkeypatch.setattr(chain.bq, "query", fake_query)
    return statements


def test_registration_deactivates_only_its_own_line(monkeypatch):
    statements = recorded(monkeypatch)
    RecordingStore().register("v1-pay", None, "{}", "", "",
                              policy_id="payments-policy")
    updates = [(s, p) for s, p in statements
               if s.strip().upper().startswith("UPDATE")]
    assert len(updates) == 1
    sql, params = updates[0]
    assert "policy_id" in sql, sql
    assert params["policy_id"] == "payments-policy"
    inserts = [(s, p) for s, p in statements
               if s.strip().upper().startswith("INSERT")]
    assert inserts and inserts[0][1]["policy_id"] == "payments-policy"


def test_registration_defaults_to_the_conduct_line(monkeypatch):
    """Every caller written before lines existed keeps its old meaning."""
    statements = recorded(monkeypatch)
    RecordingStore().register("v6", "v5", "{}", "root", "gs://uri")
    params = [p for _, p in statements if "policy_id" in p]
    assert params and all(p["policy_id"] == "conduct-policy" for p in params)


def test_a_version_name_is_never_claimed_twice_across_lines(monkeypatch):
    """`register` DELETE-then-INSERTs its own version name. Without this guard
    a genesis in one line silently swallows a version of another."""
    recorded(monkeypatch, rows_by_marker={
        "SELECT policy_id": [{"policy_id": "conduct-policy"}]})
    with pytest.raises(ValueError, match="conduct-policy"):
        RecordingStore().register("v5", None, "{}", "", "",
                                  policy_id="payments-policy")


def test_re_registering_within_the_same_line_is_still_allowed(monkeypatch):
    """The seed path re-registers a version it already owns; that is not a claim."""
    statements = recorded(monkeypatch, rows_by_marker={
        "SELECT policy_id": [{"policy_id": "conduct-policy"}]})
    RecordingStore().register("v5", "v4", "{}", "root", "gs://uri")
    assert any(s.strip().upper().startswith("INSERT") for s, _ in statements)


def test_a_legacy_row_without_policy_id_reads_as_conduct(monkeypatch):
    """Rows written before the column existed carry NULL, not a line name."""
    recorded(monkeypatch, rows_by_marker={
        "SELECT policy_id": [{"policy_id": None}]})
    with pytest.raises(ValueError, match="conduct-policy"):
        RecordingStore().register("v3", None, "{}", "", "",
                                  policy_id="payments-policy")


class FakeStore:
    def __init__(self, chains=None, rows=None):
        self._chains = chains or {}
        self._rows = rows or []

    def read(self, version):
        return self._chains.get(version, [])

    def versions(self):
        return self._rows


def test_a_parent_from_another_line_is_nothing_to_build_on():
    store = FakeStore(rows=[{"version": "v1-pay", "root": "", "policy": "{}",
                             "policy_id": "payments-policy"}])
    basis, attestation = notary.parent_basis(store, None, "v1-pay", None,
                                             policy_id="conduct-policy")
    assert basis is None and attestation is None


def test_a_genesis_parent_in_its_own_line_is_accepted():
    store = FakeStore(rows=[{"version": "v1-pay", "root": "", "policy": "{}",
                             "policy_id": "payments-policy"}])
    basis, _ = notary.parent_basis(store, None, "v1-pay", None,
                                   policy_id="payments-policy")
    assert basis and "genesis" in basis


def test_a_legacy_genesis_row_belongs_to_the_conduct_line():
    store = FakeStore(rows=[{"version": "v3", "root": "", "policy": "{}"}])
    basis, _ = notary.parent_basis(store, None, "v3", None)
    assert basis and "genesis" in basis


def test_the_active_version_is_resolved_per_line(monkeypatch):
    from caseharden.policy_server import Attestations

    rows = [
        {"version": "v5", "active": True, "policy_id": None},
        {"version": "v1-pay", "active": True, "policy_id": "payments-policy"},
        {"version": "v4", "active": False, "policy_id": "conduct-policy"},
    ]
    monkeypatch.setattr("caseharden.policy_server.identities",
                        lambda project: ("n", "e"))
    monkeypatch.setattr("caseharden.bq.access_token", lambda sa: "t")
    monkeypatch.setattr(chain.ChainStore, "versions", lambda self: rows)
    att = Attestations("devpost-hackathon-506416")
    assert att.active_version() == "v5"
    assert att.active_version("payments-policy") == "v1-pay"
    assert att.active_version("data-access-policy") is None


def test_an_empty_line_name_is_refused_before_anything_is_written(monkeypatch):
    """The server reads a falsey stored line as conduct-policy, but the scoped
    deactivation matches it exactly; an empty name registered here would be a
    second active conduct version the deactivation can never reach."""
    statements = recorded(monkeypatch)
    for name in ("", " ", "UPPER", "line name"):
        with pytest.raises(ValueError, match="line name"):
            RecordingStore().register("v9", None, "{}", "", "", policy_id=name)
    assert statements == [], "a refused name must write nothing"


def test_a_version_is_not_served_through_another_lines_route(monkeypatch):
    from caseharden import policy_server
    from caseharden.policy_server import Attestations, handler_for

    att = {"version": "v5", "state": "ATTESTED", "policy_line": "conduct-policy"}
    attestations = Attestations("devpost-hackathon-506416")
    monkeypatch.setattr(attestations, "get", lambda version: dict(att))

    sent = {}

    class Probe(handler_for(attestations)):
        def __init__(self, path):  # no socket: only do_GET's routing is under test
            self.path = path

        def _send(self, code, body):
            sent["code"], sent["body"] = code, body

    Probe("/policy/payments-policy/v5").do_GET()
    assert sent["code"] == 404, sent
    Probe("/policy/conduct-policy/v5").do_GET()
    assert sent["code"] == 200
    Probe("/policy/v5").do_GET()
    assert sent["code"] == 200


def test_the_fleet_roster_is_annotated_with_the_conduct_line(monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "register_fleet", str(REPO / "infra" / "29_register_fleet.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    rows = [
        {"version": "v5", "active": True, "policy_id": "conduct-policy",
         "root": "conductroot"},
        {"version": "v1-pay", "active": True, "policy_id": "payments-policy",
         "root": ""},
    ]
    monkeypatch.setattr(mod.bq, "access_token", lambda sa: "t")
    monkeypatch.setattr(mod.ChainStore, "versions", lambda self: rows)
    assert mod.active_version_and_root() == ("v5", "conductroot")


def test_the_line_route_parses_beside_the_legacy_one():
    assert parse_policy_path("/policy/active") == ("conduct-policy", "active")
    assert parse_policy_path("/policy/v4") == ("conduct-policy", "v4")
    assert parse_policy_path("/policy/payments-policy/active") == \
        ("payments-policy", "active")
    assert parse_policy_path("/policy/payments-policy/v1-pay") == \
        ("payments-policy", "v1-pay")
    assert parse_policy_path("/healthz") is None
    assert parse_policy_path("/policy/a/b/c") is None
