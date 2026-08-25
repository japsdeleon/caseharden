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


# --------------------------------------------------------------------------
# Which roles can reach the sealed exam
# --------------------------------------------------------------------------

def test_a_role_without_the_read_permission_does_not_reach(monkeypatch):
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: ["bigquery.jobs.create"])
    assert bq.reads_table_data("roles/bigquery.jobUser", "token") is False


def test_a_role_with_the_read_permission_reaches(monkeypatch):
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: ["bigquery.tables.getData"])
    assert bq.reads_table_data("roles/bigquery.dataViewer", "token") is True


def test_a_role_that_cannot_be_expanded_counts_as_reaching(monkeypatch):
    """Unknown is not innocent. A custom role's permissions are not in its name."""
    monkeypatch.setattr(bq, "role_permissions", lambda role, token: None)
    assert bq.reads_table_data("projects/p/roles/looksHarmless", "token") is True


def test_the_basic_roles_always_reach(monkeypatch):
    """roles.get answers for owner without listing bigquery.tables.getData.

    Believing that answer produced `roles/owner reaches=False`, which is exactly
    backwards: owner reads every table in the project. The three basic roles are
    pinned rather than expanded.
    """
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: ["resourcemanager.projects.get"])
    for role in ("roles/owner", "roles/editor", "roles/viewer"):
        assert bq.reads_table_data(role, "token") is True, role


def test_the_expansion_is_cached_per_call(monkeypatch):
    calls = []
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: calls.append(role) or [])
    monkeypatch.setattr(bq, "_ROLE_CACHE", {})
    cache = {}
    for _ in range(4):
        bq.reads_table_data("roles/bigquery.jobUser", "token", cache)
    assert calls == ["roles/bigquery.jobUser"]


def test_the_expansion_is_cached_across_calls(monkeypatch):
    """A second caller with its own cache still does not re-expand.

    This is what takes verify from 16.7s back under its SLO, so it is pinned.
    """
    calls = []
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: calls.append(role) or [])
    monkeypatch.setattr(bq, "_ROLE_CACHE", {})
    bq.reads_table_data("roles/bigquery.jobUser", "token", {})
    bq.reads_table_data("roles/bigquery.jobUser", "token", {})
    assert calls == ["roles/bigquery.jobUser"]


def test_a_role_name_that_is_not_a_role_is_not_expanded(monkeypatch):
    """No request is made for something that cannot be a role name."""
    sent = []
    monkeypatch.setattr(bq.urllib.request, "urlopen",
                        lambda *a, **k: sent.append(a) or (_ for _ in ()).throw(AssertionError))
    assert bq.role_permissions("roles/../../etc/passwd", "token") is None
    assert bq.role_permissions("deleted:serviceAccount:x", "token") is None
    assert sent == []


def test_a_custom_role_is_never_cached(monkeypatch):
    """Its permission set is editable, so caching it hides a widening.

    Grant a harmless custom role, then add bigquery.tables.getData to that role,
    and a cached answer keeps the binding out of the reach digest for the life
    of the process. The comment defending the cache claimed role permissions are
    immutable; that is true only of predefined roles.
    """
    calls = []
    monkeypatch.setattr(bq, "_ROLE_CACHE", {})
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: calls.append(role) or [])
    for _ in range(3):
        bq.reads_table_data("projects/p/roles/custom", "token", None)
    assert calls == ["projects/p/roles/custom"] * 3
    assert bq._ROLE_CACHE == {}


def test_a_stale_cached_custom_role_is_not_believed(monkeypatch):
    """The read side of the cache has to skip custom roles too.

    Asserting only that nothing is written leaves the read path untested: a
    cache pre-populated by any other means is still consulted, and the widening
    it hides is exactly the one this is meant to prevent.
    """
    monkeypatch.setattr(bq, "_ROLE_CACHE", {"projects/p/roles/custom": False})
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: ["bigquery.tables.getData"])
    assert bq.reads_table_data("projects/p/roles/custom", "token", None) is True


def test_a_predefined_role_is_still_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(bq, "_ROLE_CACHE", {})
    monkeypatch.setattr(bq, "role_permissions",
                        lambda role, token: calls.append(role) or [])
    for _ in range(3):
        bq.reads_table_data("roles/bigquery.jobUser", "token", None)
    assert calls == ["roles/bigquery.jobUser"]
