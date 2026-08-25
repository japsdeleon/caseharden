#!/usr/bin/env python3
"""The BigQuery client, which had no test and two surviving mutations.

Every claim this project makes reaches the reader through this file: the exam
score, the 403, the evidence re-scan, the chain write. An adversarial pass
mutated it twice and the whole suite stayed green. Both mutations are pinned
here:

  named parameters silently dropped, which turns every chain write into an
  interpolated statement

  insertErrors ignored, which is the function's own docstring: a caller reading
  only the status code records a tamper that never landed and then reports a
  chain that verifies as proof of nothing

run:  python3 -m pytest tests -q
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from caseharden import bq  # noqa: E402


class _Response:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return io.BytesIO(self._payload)

    def __exit__(self, *_):
        return False


def _capture(monkeypatch, payload):
    """Answer the next request with `payload`, and keep the request itself."""
    sent = {}

    def fake_urlopen(request, *_a, **_k):
        sent["url"] = request.full_url
        sent["body"] = json.loads(request.data.decode()) if request.data else None
        sent["headers"] = dict(request.headers)
        return _Response(payload)

    monkeypatch.setattr(bq.urllib.request, "urlopen", fake_urlopen)
    return sent


OK = {"jobComplete": True, "schema": {"fields": [{"name": "n"}]},
      "rows": [{"f": [{"v": "1"}]}]}


# --------------------------------------------------------------------------
# Named parameters
# --------------------------------------------------------------------------

def test_named_parameters_reach_the_request():
    """Dropping them turns every chain write back into an interpolated statement."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        sent = _capture(monkeypatch, OK)
        bq.query("SELECT @n", "p-project", "token", params={"n": "v4"})
    assert sent["body"]["parameterMode"] == "NAMED"
    assert sent["body"]["queryParameters"] == [
        {"name": "n", "parameterType": {"type": "STRING"},
         "parameterValue": {"value": "v4"}}]


def test_a_query_with_no_parameters_carries_no_parameter_block():
    with pytest.MonkeyPatch.context() as monkeypatch:
        sent = _capture(monkeypatch, OK)
        bq.query("SELECT 1", "p-project", "token")
    assert "queryParameters" not in sent["body"]
    assert "parameterMode" not in sent["body"]


def test_every_supported_parameter_type_is_encoded_for_the_rest_api():
    encoded = bq._parameters({"s": "x", "i": 3, "f": 1.5, "b": True})
    by_name = {p["name"]: p for p in encoded}
    assert by_name["s"]["parameterType"]["type"] == "STRING"
    assert by_name["i"]["parameterType"]["type"] == "INT64"
    assert by_name["f"]["parameterType"]["type"] == "FLOAT64"
    # BOOL must be "true"/"false", not Python's "True"/"False".
    assert by_name["b"]["parameterType"]["type"] == "BOOL"
    assert by_name["b"]["parameterValue"]["value"] == "true"


def test_an_unsupported_parameter_type_is_refused_rather_than_stringified():
    with pytest.raises(ValueError):
        bq._parameters({"payload": {"a": 1}})


def test_a_payload_carrying_quotes_and_newlines_survives_as_a_parameter():
    """Chain payloads are JSON documents full of quotes. They are values, never SQL."""
    payload = json.dumps({"note": 'he said "no"\nthen left', "sql": "'; DROP"})
    with pytest.MonkeyPatch.context() as monkeypatch:
        sent = _capture(monkeypatch, OK)
        bq.query("INSERT ... VALUES (@p)", "p-project", "token", params={"p": payload})
    assert sent["body"]["queryParameters"][0]["parameterValue"]["value"] == payload
    assert "DROP" not in sent["body"]["query"]


# --------------------------------------------------------------------------
# Answers that are not answers
# --------------------------------------------------------------------------

def test_a_query_that_did_not_finish_is_not_an_empty_result():
    with pytest.MonkeyPatch.context() as monkeypatch:
        _capture(monkeypatch, {"jobComplete": False})
        with pytest.raises(bq.IncompleteResult):
            bq.query("SELECT 1", "p-project", "token")


def test_a_partial_page_is_not_a_complete_answer():
    with pytest.MonkeyPatch.context() as monkeypatch:
        _capture(monkeypatch, dict(OK, pageToken="more"))
        with pytest.raises(bq.IncompleteResult):
            bq.query("SELECT 1", "p-project", "token")


def test_an_error_in_a_200_body_is_still_an_error():
    with pytest.MonkeyPatch.context() as monkeypatch:
        _capture(monkeypatch, {"error": {"code": 403, "status": "PERMISSION_DENIED",
                                         "message": "Access Denied"}})
        with pytest.raises(bq.BigQueryError) as exc:
            bq.query("SELECT 1", "p-project", "token")
    assert exc.value.payload["error"]["code"] == 403


# --------------------------------------------------------------------------
# Streaming inserts
# --------------------------------------------------------------------------

def test_rejected_rows_are_raised_rather_than_returned_as_success():
    """insertAll answers 200 with insertErrors when individual rows are rejected."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        _capture(monkeypatch, {"insertErrors": [
            {"index": 0, "errors": [{"reason": "invalid", "message": "no such field"}]}]})
        with pytest.raises(bq.BigQueryError) as exc:
            bq.insert_rows([{"event_id": "e_1"}], "p-project", "dataset", "turns", "token")
    assert "no such field" in str(exc.value)


def test_an_accepted_insert_returns_quietly():
    with pytest.MonkeyPatch.context() as monkeypatch:
        sent = _capture(monkeypatch, {"kind": "bigquery#tableDataInsertAllResponse"})
        bq.insert_rows([{"event_id": "e_1"}], "p-project", "dataset", "turns", "token")
    assert sent["body"] == {"rows": [{"json": {"event_id": "e_1"}}]}


# --------------------------------------------------------------------------
# Names that reach a quoted identifier or a URL
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["bad`project", "Project", "p", "x" * 70,
                                  "trailing-", "-leading", "has space", ""])
def test_a_name_that_could_close_an_identifier_is_refused(name):
    assert not bq.NAME_RE.match(name)
    with pytest.raises(ValueError):
        bq.qualified_table(name, "conduct_train")
    with pytest.raises(ValueError):
        bq.query("SELECT 1", name, "token")
    with pytest.raises(ValueError):
        bq.get_dataset(name, "conduct_train", "token")
    with pytest.raises(ValueError):
        bq.project_iam_bindings(name, "token")
    with pytest.raises(ValueError):
        bq.insert_rows([], name, "dataset", "turns", "token")


def test_the_token_never_reaches_a_url_or_a_command_argument():
    """Both are visible in the local process table."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        sent = _capture(monkeypatch, OK)
        bq.query("SELECT 1", "p-project", "s3cret-token")
    assert "s3cret-token" not in sent["url"]
    assert sent["headers"]["Authorization"] == "Bearer s3cret-token"


def test_gcloud_is_pinned_to_this_projects_configuration():
    """The machine that builds this has other gcloud configurations on it."""
    assert bq.gcloud_env()["CLOUDSDK_ACTIVE_CONFIG_NAME"] == bq.GCLOUD_CONFIG
