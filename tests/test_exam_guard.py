#!/usr/bin/env python3
"""A line with no sealed exam can gate nothing.

Only `conduct-policy` has a sealed exam. Day 10 registered `payments-policy`
at a floor with no exam, and `promote`/`seed` would still have run the gate
against holdout_sealed — the CONDUCT exam — stamping a payments candidate
with a grade measured on the wrong exam. What these tests pin is the guard:
an unexamined line is refused before any token is minted or anything is
loaded, and the exam map itself stays exactly one line wide until a second
exam is sealed.

run:  python3 -m pytest tests/test_exam_guard.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from caseharden import notary  # noqa: E402

CANDIDATE = str(REPO / "policies" / "v1-pay.json")


def _no_network(monkeypatch):
    def boom(project, args):
        raise AssertionError("network path reached")
    monkeypatch.setattr(notary, "_tokens", boom)


def test_promote_on_an_unexamined_line_is_refused_offline(monkeypatch, capsys):
    _no_network(monkeypatch)
    code = notary.main(["promote", "--version", "v2-pay", "--parent", "v1-pay",
                        "--candidate", CANDIDATE,
                        "--policy-id", "payments-policy"])
    assert code == 5
    out = capsys.readouterr().out
    assert "payments-policy has no sealed exam" in out
    assert "v2-pay was not promoted and nothing was written to the chain." in out


def test_seed_on_an_unexamined_line_is_refused_offline(monkeypatch, capsys):
    _no_network(monkeypatch)
    code = notary.main(["seed", "--version", "v2-pay",
                        "--candidate", CANDIDATE,
                        "--policy-id", "payments-policy"])
    assert code == 5
    out = capsys.readouterr().out
    assert "payments-policy has no sealed exam" in out
    assert "v2-pay was not promoted and nothing was written to the chain." in out


def test_the_conduct_line_passes_the_guard(monkeypatch):
    """The default line has an exam, so execution reaches the network path."""
    def past_the_guard(project, args):
        raise RuntimeError("past the guard: tokens requested")
    monkeypatch.setattr(notary, "_tokens", past_the_guard)
    with pytest.raises(RuntimeError, match="past the guard"):
        notary.main(["promote", "--version", "v6", "--parent", "v5",
                     "--candidate", CANDIDATE])


def test_the_exam_map_is_exactly_one_line_wide():
    """Widening this map is a decision, not a side effect; pin today's shape."""
    assert notary.LINE_EXAMS == {"conduct-policy": "holdout_sealed"}


# --------------------------------------------------------------------------
# genesis: a line's first version and nothing after it
# --------------------------------------------------------------------------

class _GenesisStore:
    """register() marks its row active, so a second genesis in a live line
    would replace the floor. These tests pin the refusal."""

    def __init__(self, rows):
        self.rows = rows
        self.registered = []

    def read(self, version):
        return []

    def versions(self):
        return self.rows

    def register(self, *a, **k):
        self.registered.append((a, k))


def _store(monkeypatch, rows):
    store = _GenesisStore(rows)
    monkeypatch.setattr(notary, "_tokens",
                        lambda project, args: (None, None, store))
    return store


def test_a_second_genesis_in_a_line_is_refused(monkeypatch, capsys):
    store = _store(monkeypatch, [{"version": "v1-pay",
                                  "policy_id": "payments-policy"}])
    code = notary.main(["genesis", "--version", "v2-pay",
                        "--policy", CANDIDATE,
                        "--policy-id", "payments-policy"])
    assert code == 2
    out = capsys.readouterr().out
    assert "not its genesis" in out and "v1-pay" in out
    assert "nothing was written" in out
    assert store.registered == []


def test_a_legacy_null_row_counts_as_conduct_for_genesis(monkeypatch, capsys):
    store = _store(monkeypatch, [{"version": "v5", "policy_id": None}])
    code = notary.main(["genesis", "--version", "v6", "--policy", CANDIDATE])
    assert code == 2
    assert store.registered == []


def test_a_true_first_genesis_still_registers(monkeypatch, capsys):
    store = _store(monkeypatch, [{"version": "v5", "policy_id": None}])
    code = notary.main(["genesis", "--version", "v1-new", "--policy", CANDIDATE,
                        "--policy-id", "brand-new-line"])
    assert code == 0
    assert len(store.registered) == 1
