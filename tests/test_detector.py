#!/usr/bin/env python3
"""The detector template: four families, one SQL builder, no caller input in it."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "agents", "detector"))

import families  # noqa: E402

TABLE = "devpost-hackathon-506416.conduct_live.turns"


def test_every_family_builds_a_query():
    for family in families.FAMILIES:
        sql = families.scan_sql(family, TABLE, 72)
        assert sql.startswith(("SELECT", "WITH")), family
        assert f"`{TABLE}`" in sql, family


def test_a_table_identifier_cannot_close_the_quote(monkeypatch):
    """The docstring used to claim the caller had validated this. It had not.

    A backtick closes the identifier and appends whatever follows to the query.
    """
    for bad in (TABLE + "` WHERE FALSE; SELECT 'injected' AS proof --",
                TABLE + "; DROP TABLE x",
                "p.d",
                "p.d.t.u",
                "P.d.t",
                ""):
        with pytest.raises(ValueError):
            families.scan_sql("cross-tenant", bad, 72)


def test_the_window_is_bounded():
    for bad in (0, -1, 24 * 30 + 1, 10**9):
        with pytest.raises(ValueError):
            families.scan_sql("cross-tenant", TABLE, bad)


def test_every_query_is_bounded_by_the_partition_and_the_row_cap():
    """An unbounded scan against a growing table is the most expensive mistake here."""
    for family in families.FAMILIES:
        sql = families.scan_sql(family, TABLE, 72)
        assert "TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 72 HOUR)" in sql, family
        assert f"LIMIT {families.ROW_CAP}" in sql, family


def test_the_sequencing_check_ignores_writes_with_no_account():
    """Absent is not "some other account", and guessing is how a finding is invented."""
    sql = families.scan_sql("privilege-sequencing", TABLE, 72)
    assert "c.account_id IS NOT NULL" in sql
    assert "NOT IN UNNEST(" in sql


def test_the_fourth_family_is_the_one_the_specification_names():
    """It was refund-velocity, a volume check, until an audit caught the swap."""
    assert "privilege-sequencing" in families.FAMILIES
    assert "refund-velocity" not in families.FAMILIES
    assert families.FAMILIES["privilege-sequencing"].get("sequencing") is True
