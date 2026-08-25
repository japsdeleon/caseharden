#!/usr/bin/env python3
"""What the Proposer's own code has to get right, without a model or a cloud.

Three things are worth pinning here and nothing else is:

  the grammar handed to the model is derived from dsl.py, so a predicate added
  to the DSL cannot silently go missing from the prompt;

  the object reader finds a candidate inside an answer that carries stray prose,
  because a draft that cannot be read is a rejection that never gets recorded;

  `base_rate` refuses a field outside the numeric vocabulary before it reaches
  SQL, since the field name is the one part of that query a model chooses.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "agents", "proposer"))

import draft  # noqa: E402  (agents/proposer/draft.py)

from caseharden.dsl import NUMERIC_FIELDS, PREDICATE_FIELDS, PREDICATE_OPS  # noqa: E402


def test_the_grammar_the_model_sees_is_the_grammar_the_parser_enforces():
    grammar = json.loads(draft.grammar())
    assert set(grammar["predicate_ops"]) == set(PREDICATE_OPS)
    named = set(grammar["string_fields"] + grammar["numeric_fields"]
                + grammar["array_fields"])
    assert named == set(PREDICATE_FIELDS)


def test_the_answer_key_is_not_in_the_grammar():
    # The one field set a candidate must never be able to cite. A model that can
    # write `label = attack` scores a perfect catch rate and detects nothing.
    grammar = draft.grammar()
    for forbidden in ("label", "is_attack_event", "account_id", "session_id"):
        assert forbidden not in grammar


def test_a_candidate_is_found_inside_stray_prose():
    answer = ('Here is the draft you asked for.\n'
              '{"candidate": {"version": "v5", "rules": []}, "rationale": "x"}\n'
              'Let me know if you want it narrower.')
    assert draft.first_json_object(answer)["candidate"]["version"] == "v5"


def test_a_nested_object_does_not_end_the_scan_early():
    answer = '{"candidate": {"rules": [{"all_of": [{"op": "present"}]}]}, "rationale": "y"}'
    found = draft.first_json_object(answer)
    assert found["rationale"] == "y"
    assert found["candidate"]["rules"][0]["all_of"][0]["op"] == "present"


def test_a_brace_inside_a_string_does_not_end_the_object():
    """An adversarial pass found this by writing prose the model would write.

    Counting braces without tracking strings ended the object at the first
    closing brace inside the rationale, so a perfectly valid candidate was
    recorded in the chain as a rejected draft and the model was blamed for it.
    """
    assert draft.first_json_object(
        '{"candidate": {"version": "v5"}, "rationale": "denies x } leaves y"}'
    )["candidate"]["version"] == "v5"
    assert draft.first_json_object(
        r'{"rationale": "he said \" then } stopped", "candidate": {"version": "v6"}}'
    )["candidate"]["version"] == "v6"


def test_an_unparseable_answer_reads_as_empty_rather_than_raising():
    # The caller records this as a rejected draft. Raising here would lose the
    # rejection, which is the one outcome the DRAFT-REJECTED link exists for.
    assert draft.first_json_object("no json here at all") == {}
    assert draft.first_json_object('{"broken": ') == {}


def test_base_rate_refuses_a_field_outside_the_numeric_vocabulary():
    for field in ("label", "is_attack_event", "session_id", "tool_name",
                  "amount_cents; DROP TABLE x", "`"):
        answer = draft.base_rate(field, 0.5)
        assert "error" in answer, field
        assert set(answer["numeric_fields"]) == set(NUMERIC_FIELDS)


def test_base_rate_accepts_every_numeric_field_of_the_vocabulary(monkeypatch):
    seen = {}

    class FakeBQ:
        BigQueryError = RuntimeError

        @staticmethod
        def qualified_table(project, dataset, table="turns"):
            return f"{project}.{dataset}.{table}"

        @staticmethod
        def query(sql, project, token, **kwargs):
            seen["sql"] = sql
            seen["params"] = kwargs.get("params")
            return [{"turns": "1", "tool_calls": "1", "at_or_above": "1",
                     "between_here_and_075": "0"}]

    # `from caseharden import bq` binds the package attribute, so patching
    # sys.modules alone leaves the real client in place.
    monkeypatch.setattr("caseharden.bq", FakeBQ)
    monkeypatch.setattr(draft.creds, "access_token", lambda: "t")
    for field in NUMERIC_FIELDS:
        answer = draft.base_rate(field, 0.61234)
        assert answer["field"] == field
        assert answer["at_least"] == 0.61234
        # The threshold is a bound parameter, never text in the statement. The
        # value is distinctive so the check cannot pass on a coincidence: the
        # query does carry a literal 0.75, which is the active threshold this
        # count is expressed relative to.
        assert "0.61234" not in seen["sql"]
        assert "@t" in seen["sql"]
        assert seen["params"] == {"t": 0.61234}


def test_self_check_raises_if_the_proposer_can_read_the_exam(monkeypatch):
    """The loudest possible failure, because a quiet one invalidates everything.

    If this ever returns rows, the isolation the whole entry rests on is not
    holding, and a Proposer that scores itself against the exam must not be able
    to look like a passing run.
    """
    class ReadableBQ:
        BigQueryError = RuntimeError

        @staticmethod
        def qualified_table(project, dataset, table="turns"):
            return f"{project}.{dataset}.{table}"

        @staticmethod
        def query(sql, project, token, **kwargs):
            return [{"event_id": "e1", "label": "cross-tenant-egress"}]

    monkeypatch.setattr("caseharden.bq", ReadableBQ)
    monkeypatch.setattr(draft.creds, "access_token", lambda: "t")
    with pytest.raises(RuntimeError, match="READ the sealed holdout"):
        draft.self_check()


def test_self_check_records_the_refusal_verbatim(monkeypatch):
    class RefusingBQ:
        class BigQueryError(RuntimeError):
            def __init__(self, payload):
                self.payload = payload
                super().__init__("refused")

        @staticmethod
        def qualified_table(project, dataset, table="turns"):
            return f"{project}.{dataset}.{table}"

        @classmethod
        def query(cls, sql, project, token, **kwargs):
            raise cls.BigQueryError({"error": {
                "code": 403, "status": "PERMISSION_DENIED",
                "message": "Access Denied: Table holdout_sealed.turns"}})

    monkeypatch.setattr("caseharden.bq", RefusingBQ)
    monkeypatch.setattr(draft.creds, "access_token", lambda: "t")
    monkeypatch.setattr(draft.creds, "attached_service_account", lambda: None)
    answer = draft.self_check()
    assert answer["http_code"] == 403
    assert answer["status"] == "PERMISSION_DENIED"
    assert "holdout_sealed" in answer["message"]
    assert answer["permission"] == "bigquery.tables.getData"
    assert answer["principal"].startswith("proposer-sa@")
