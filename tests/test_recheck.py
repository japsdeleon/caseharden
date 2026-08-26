#!/usr/bin/env python3
"""The offline re-check has to fail. That is the only thing worth testing about it.

A checker that passes on a clean fixture proves nothing on its own; the fixture
was exported from a chain that verified. So each test below tampers with the
committed fixture in a different way, and asserts the re-check refuses it.

The last one is the point of the whole fixture. It rewrites every hash and forges
the certificate to match, which defeats every consistency check, and is still
caught, because the Examiner's numbers are replayed from the committed seeded
generator rather than believed.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, str(ROOT))

from caseharden import chain  # noqa: E402
from caseharden.recheck import recheck  # noqa: E402

FIXTURE = ROOT / "fixtures" / "v5"

pytestmark = pytest.mark.skipif(
    not (FIXTURE / "chain.jsonl").exists(),
    reason="no exported fixture; run infra/120_export_fixture.py")


def copy(tmp_path: Path) -> Path:
    out = tmp_path / "v5"
    shutil.copytree(FIXTURE, out)
    return out


def links_of(directory: Path) -> list:
    return [json.loads(line) for line in
            (directory / "chain.jsonl").read_text().splitlines() if line.strip()]


def write(directory: Path, rows: list) -> None:
    (directory / "chain.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n")


def rehash(rows: list) -> list:
    """Rebuild the whole chain, the way a careful tamper would."""
    prev = ""
    for row in rows:
        row["prev_hash"] = prev
        row["link_hash"] = chain.link_hash(row["version"], row["seq"], row["kind"],
                                           prev, row["payload"])
        prev = row["link_hash"]
    return rows


def test_the_committed_fixture_passes(tmp_path):
    assert recheck(copy(tmp_path)) == 0


def test_an_edited_payload_is_caught_by_the_link_hash(tmp_path):
    directory = copy(tmp_path)
    rows = links_of(directory)
    for row in rows:
        if row["kind"] == "VERDICT":
            row["payload"]["disposition"] = "false positive"
    write(directory, rows)
    assert recheck(directory, skip_replay=True) == 1


def test_a_rewritten_chain_is_caught_by_the_sealed_certificate(tmp_path):
    """Rewriting every hash defeats the walk. It does not defeat the seal."""
    directory = copy(tmp_path)
    rows = links_of(directory)
    for row in rows:
        if row["kind"] == "VERDICT":
            row["payload"]["disposition"] = "false positive"
    write(directory, rehash(rows))
    assert recheck(directory, skip_replay=True) == 1


def test_a_dropped_link_is_caught(tmp_path):
    directory = copy(tmp_path)
    rows = [r for r in links_of(directory) if r["kind"] != "HOLDOUT-DENIED"]
    write(directory, rehash(rows))
    assert recheck(directory, skip_replay=True) == 1


def test_an_invented_catch_rate_is_caught_by_the_replay(tmp_path):
    """Every hash rebuilt and the certificate forged to match. Still refused.

    This is what the fixture is for. Consistency checks only prove a record was
    not edited after it was sealed. The replay proves the numbers in it were
    measured, because the generator is seeded and the Examiner has no model.
    """
    directory = copy(tmp_path)
    rows = links_of(directory)
    for row in rows:
        if row["kind"] == "EXAM":
            row["payload"]["holdout"]["privilege-sequencing"]["denied_sessions"] = 10
    rows = rehash(rows)
    write(directory, rows)
    certificate = json.loads((directory / "certificate.json").read_text())
    certificate["root"] = rows[-1]["link_hash"]
    certificate["links"] = [{"seq": r["seq"], "kind": r["kind"], "hash": r["link_hash"]}
                            for r in rows]
    (directory / "certificate.json").write_text(json.dumps(certificate, indent=2))

    assert recheck(directory, skip_replay=True) == 1, (
        "the approval binding should still catch a rewritten chain")
    assert recheck(directory) == 1, "the replay must refuse an invented catch rate"
