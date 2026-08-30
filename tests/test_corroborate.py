#!/usr/bin/env python3
"""What the Notary checks before it seals a bundle's claims into the chain.

Why these tests exist. The disposition became the value that decides whether a
policy version is justified at all, and the component that writes the chain was
not reading it. `corroborate` selected `disposition` in its query and never
compared it, so a bundle claiming `confirmed abuse` over a row that says
`benign` sealed a VERDICT link asserting a disposition the human never gave, and
promoted on it. Two independent adversarial passes reached that from opposite
directions.

The citation had the matching hole. It was written to `review.decisions` and
nowhere else, and `analyst-sa` holds WRITER on that dataset, which carries DML.
So the one field saying which policy a verdict was about could be rewritten
after the Notary had sealed the link that relied on it, while THREATS.md
section 5 protects the rationale from exactly that by matching the bundle
against the stored row.

The BigQuery reads are stubbed. This is about what the function refuses, not
about the warehouse, and the repo's offline promise is that the suite runs on a
clean checkout with no credentials.

run:  python3 -m pytest tests/test_corroborate.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from caseharden import notary, verdicts  # noqa: E402

JOB = "europe-west3:job_5UcJoBBEaZWU0"
VERDICT_ID = "vd_1"
APPROVAL_ID = "ap_1"


def _row(**over) -> dict:
    row = {"kind": "VERDICT", "analyst": "analyst@caseharden.example",
           "subject": JOB, "disposition": verdicts.DRAFTS,
           "rationale": "tool calls outside the session's declared scope",
           "ma_verdict": "CLEAN", "approved": None,
           "cited_policy_id": "conduct-policy", "cited_version": "v5",
           "citation_source": "ANALYST"}
    row.update(over)
    return row


def _verdict(**over) -> dict:
    payload = {"decision_id": VERDICT_ID, "disposition": verdicts.DRAFTS,
               "rationale": "tool calls outside the session's declared scope",
               "cited_policy_id": "conduct-policy", "cited_version": "v5",
               "citation_source": "ANALYST"}
    payload.update(over)
    return payload


@pytest.fixture
def stubbed(monkeypatch):
    """A completed BigQuery job and one review row per decision id.

    Returns a dict the test mutates to say what the warehouse holds.
    """
    stored = {VERDICT_ID: _row(),
              APPROVAL_ID: _row(kind="APPROVAL", subject="v5", approved="true",
                                disposition=None)}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(notary.urllib.request, "urlopen",
                        lambda *a, **k: _Response())
    monkeypatch.setattr(notary.json, "load",
                        lambda *_: {"status": {"state": "DONE"}})

    def query(sql, project, token, **kwargs):
        decision_id = (kwargs.get("params") or {}).get("id")
        row = stored.get(decision_id)
        return [row] if row else []

    monkeypatch.setattr(notary.bq, "query", query)
    return stored


def _run(stubbed, verdict=None, approval=None):
    args = SimpleNamespace(project="devpost-hackathon-506416", version="v5")
    bundle = {"approval": approval or {"decision_id": APPROVAL_ID}}
    return notary.corroborate(args, "token", {"job_id": JOB},
                              verdict or _verdict(), bundle)


def test_a_bundle_that_matches_the_rows_is_corroborated(stubbed):
    assert _run(stubbed) is None


def test_a_bundle_claiming_a_disposition_the_row_does_not_carry_is_refused(stubbed):
    """The chain would otherwise assert a disposition the human never gave."""
    stubbed[VERDICT_ID] = _row(disposition="benign")
    with pytest.raises(SystemExit) as raised:
        _run(stubbed)
    assert "benign" in str(raised.value) and "Nothing written" in str(raised.value)


@pytest.mark.parametrize("terminal", verdicts.TERMINAL)
def test_a_terminal_verdict_cannot_justify_a_version(stubbed, terminal):
    """Agreeing with the row is not enough when the row closes the review.

    `notary seed --bundle` is runnable by hand, so the driver refusing to draft
    is not the same as the promoter refusing to promote.
    """
    stubbed[VERDICT_ID] = _row(disposition=terminal)
    with pytest.raises(SystemExit) as raised:
        _run(stubbed, verdict=_verdict(disposition=terminal))
    assert verdicts.DRAFTS in str(raised.value)


@pytest.mark.parametrize("column,forged", [
    ("cited_policy_id", "payments-policy"),
    ("cited_version", "v4"),
    ("citation_source", "DEFAULTED"),
    ("advisory_recommendation", "confirmed abuse"),
    ("advisory_rule", "tool-call-on-injected-turn"),
    ("advisory_confidence", 0.99),
    ("advisory_source", "RECOMMENDER"),
])
def test_a_claim_about_the_review_the_row_does_not_carry_is_refused(stubbed, column,
                                                                   forged):
    """Every column the chain asserts, not only the citation.

    The advisory is the record of what the machine put in front of the human. An
    influence record the chain never sealed can be rewritten afterwards by the
    identity that wrote it, and `analyst-sa` holds WRITER on that dataset.
    """
    with pytest.raises(SystemExit) as raised:
        _run(stubbed, verdict=_verdict(**{column: forged}))
    assert column in str(raised.value)


def test_an_advisory_the_row_carries_and_the_bundle_drops_is_refused(stubbed):
    """The other direction: a chain link quietly omitting the machine's influence."""
    stubbed[VERDICT_ID] = _row(advisory_recommendation="confirmed abuse",
                               advisory_source="SURFACE")
    with pytest.raises(SystemExit) as raised:
        _run(stubbed)
    assert "advisory_recommendation" in str(raised.value)


def test_a_matching_advisory_is_corroborated(stubbed):
    """And the confidence survives BigQuery returning every value as text."""
    stubbed[VERDICT_ID] = _row(advisory_recommendation="confirmed abuse",
                               advisory_rule="tool-call-on-injected-turn",
                               advisory_confidence="0.82",
                               advisory_source="SURFACE")
    assert _run(stubbed, verdict=_verdict(
        advisory_recommendation="confirmed abuse",
        advisory_rule="tool-call-on-injected-turn",
        advisory_confidence=0.82,
        advisory_source="SURFACE")) is None


def test_an_uncited_verdict_still_corroborates_when_both_sides_agree(stubbed):
    """A verdict citing nothing is a real state, not a mismatch to refuse."""
    stubbed[VERDICT_ID] = _row(cited_policy_id=None, cited_version=None,
                               citation_source="NONE")
    assert _run(stubbed, verdict=_verdict(
        cited_policy_id=None, cited_version=None, citation_source="NONE")) is None


def test_a_rationale_that_differs_is_still_refused(stubbed):
    """The check this file's new ones were modelled on, kept covered."""
    with pytest.raises(SystemExit) as raised:
        _run(stubbed, verdict=_verdict(rationale="something else entirely"))
    assert "differs from the row" in str(raised.value)


def test_a_verdict_with_no_row_behind_it_is_refused(stubbed):
    stubbed.pop(VERDICT_ID)
    with pytest.raises(SystemExit) as raised:
        _run(stubbed)
    assert "not in review.decisions" in str(raised.value)


def test_a_bundle_understating_the_row_is_also_refused(stubbed):
    """The other direction, and the one only the equality check catches.

    Row says `confirmed abuse`, bundle claims `benign`. The requirement that a
    promotion rest on `confirmed abuse` is satisfied by the row, so nothing but
    comparing the two stops a chain link recording a verdict the human did not
    give. Without this the mismatch test passed on the DRAFTS check instead and
    the comparison could be deleted unnoticed.
    """
    with pytest.raises(SystemExit) as raised:
        _run(stubbed, verdict=_verdict(disposition="benign"))
    message = str(raised.value)
    assert "benign" in message and verdicts.DRAFTS in message
    assert "Nothing written" in message


# --------------------------------------------------------------------------
# The three files that have to agree about one column list
# --------------------------------------------------------------------------

DRIVER = (REPO / "infra" / "110_run_loop.py").read_text()


def _driver_select() -> str:
    """The SELECT list in `decisions()`, which is what reaches the bundle."""
    start = DRIVER.index("def decisions(")
    return DRIVER[start:DRIVER.index("params=", start)]


def test_the_driver_selects_every_column_the_notary_corroborates():
    """A column not selected reaches the bundle as None and refuses a promotion.

    The citation columns were corroborated before the poll selected them, so a
    verdict that cited a policy would have been refused at the seal for a
    disagreement created by the SELECT list rather than by anything an analyst
    did. Nothing produced a citation yet, so it would have surfaced on the first
    real one.
    """
    select = _driver_select()
    missing = [c for c in notary.CORROBORATED_VERDICT_COLUMNS if c not in select]
    assert not missing, (
        f"infra/110_run_loop.py's decisions() does not select {missing}, which "
        f"caseharden/notary.py corroborates against the stored row")


def test_the_bundle_carries_every_column_the_notary_corroborates():
    block = DRIVER[DRIVER.index('"verdict": {'):]
    block = block[:block.index("\n        },")]
    missing = [c for c in notary.CORROBORATED_VERDICT_COLUMNS
               if f'"{c}"' not in block]
    assert not missing, (
        f"the bundle's verdict block does not carry {missing}, so the Notary "
        f"compares None against a stored value")


def test_a_confidence_survives_bigquery_returning_it_as_text():
    """`bq.query` stringifies every value, so 0.82 comes back as '0.82'."""
    assert notary._same_field("0.82", 0.82)
    assert notary._same_field(0.82, "0.82")
    # The pair a text comparison gets wrong. `str(0.8)` is "0.8", so a stored
    # "0.80" would read as a mismatch and refuse a promotion over a formatting
    # difference. BigQuery's REST encoding is not required to hand back the
    # spelling that was written.
    assert notary._same_field("0.80", 0.8)
    assert notary._same_field("8e-01", 0.8)
    assert not notary._same_field("0.82", 0.81)
    assert notary._same_field(None, None)
    assert not notary._same_field(None, "0.82")
    assert not notary._same_field("ANALYST", "DEFAULTED")
    assert notary._same_field("ANALYST", "ANALYST")
