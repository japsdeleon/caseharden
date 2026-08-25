#!/usr/bin/env python3
"""The Caseharden conduct-policy DSL.

A policy is a list of rules. A rule denies a turn when every predicate in its
`all_of` list matches that turn. A turn no rule denies is allowed.

Three properties this grammar holds on purpose:

  There is no allow verb. `action` is the literal "deny" and nothing else
  parses, so no draft can widen authority by *adding* a rule. It can still widen
  by dropping a rule or by adding a predicate to one, and the grammar cannot
  stop either. That is the Examiner's structural monotonicity check, not this
  file's: a rule denies when all of its predicates match, so a candidate rule
  covers an active rule only when its predicate set is a subset. See
  `interpreter.structurally_monotonic`.

  The feature vocabulary is closed. `field` is a Literal over the columns the
  generator declares as predicate fields. `label` and `is_attack_event` are the
  answer key and are not in it, so a candidate cannot cite the answer even if it
  is somehow handed a labelled row. Neither is `account_id`: a per-call
  identifier lets a candidate name the exact accounts in the exam, catch a whole
  family, deny nothing legitimate, and generalize to nothing.

  Unknown keys are rejected rather than ignored. Every model sets
  extra="forbid", so a draft naming a predicate that does not exist fails
  validation with the offending name in the message. That rejection is written
  to the chain as its own link instead of being retried silently.

Literals are constrained at parse time, because a policy is authored by a
language model and compiled into SQL. Strings must match LITERAL_RE, and the
compiler escapes as well. Numbers must be finite and must not be booleans:
`1e400` is ordinary valid JSON, parses to `inf`, and compiles to a bare `inf`
that BigQuery reads as a column name, so the two engines disagree and the query
fails rather than the draft being rejected.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional, Union, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing_extensions import Annotated, Literal

# Columns a predicate may reference. Must equal generate_conduct.PREDICATE_FIELDS;
# tests/test_gate.py asserts that, because a field present in one and absent from
# the other is either a column no candidate can use or a candidate referencing a
# column that does not exist.
STRING_FIELDS = ("tool_name", "tenant_id", "target_tenant_id", "ma_verdict")
NUMERIC_FIELDS = ("amount_cents", "ma_prompt_injection_score", "ma_jailbreak_score", "turn_index")
ARRAY_FIELDS = ("declared_scope",)
PREDICATE_FIELDS = tuple(sorted(STRING_FIELDS + NUMERIC_FIELDS + ARRAY_FIELDS))

StringField = Literal[STRING_FIELDS]
NumericField = Literal[NUMERIC_FIELDS]
ScalarField = Literal[tuple(sorted(STRING_FIELDS + NUMERIC_FIELDS))]

# Literals are model-authored and end up inside a SQL string. Everything the
# vocabulary needs is here; everything an injection needs is not.
LITERAL_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,64}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Equals(_Strict):
    """field = value. A NULL field does not match, exactly as in SQL."""

    op: Literal["equals"]
    field: StringField
    value: str

    @field_validator("value")
    @classmethod
    def _safe(cls, v: str) -> str:
        if not LITERAL_RE.match(v):
            raise ValueError(f"literal outside the permitted character set: {v!r}")
        return v


class InSet(_Strict):
    """field IN (values)."""

    op: Literal["in_set"]
    field: StringField
    values: Annotated[List[str], Field(min_length=1, max_length=32)]

    @field_validator("values")
    @classmethod
    def _safe(cls, vs: List[str]) -> List[str]:
        for v in vs:
            if not LITERAL_RE.match(v):
                raise ValueError(f"literal outside the permitted character set: {v!r}")
        return vs


class AtLeast(_Strict):
    """field >= value, on numeric columns only. A NULL field does not match."""

    op: Literal["at_least"]
    field: NumericField
    value: float

    @field_validator("value", mode="before")
    @classmethod
    def _finite(cls, v: object) -> object:
        if isinstance(v, bool):
            raise ValueError("a threshold must be a number, not a boolean")
        if isinstance(v, str):
            raise ValueError(f"a threshold must be a number, not a string: {v!r}")
        if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
            raise ValueError(f"a threshold must be finite: {v!r}")
        return v


class Present(_Strict):
    """field IS NOT NULL. The usual way to say "this turn called a tool"."""

    op: Literal["present"]
    field: ScalarField


class OutsideDeclaredScope(_Strict):
    """The turn called a tool the session did not declare it could call.

    Takes no field, because it is the one predicate that reads the repeated
    column, and comparing a scalar to an array is not something the vocabulary
    should let a draft express in general.
    """

    op: Literal["outside_declared_scope"]


class TenantMismatch(_Strict):
    """The tool call acted on a tenant other than the session's own."""

    op: Literal["tenant_mismatch"]


Predicate = Annotated[
    Union[Equals, InSet, AtLeast, Present, OutsideDeclaredScope, TenantMismatch],
    Field(discriminator="op"),
]


def _ops() -> tuple:
    """Every `op` the grammar accepts, derived rather than restated.

    A hand-kept list is a list that goes stale the first time a predicate is
    added. tests/test_gate.py compiles one of each, and reads the roster here.
    """
    union = get_args(Predicate)[0]
    return tuple(get_args(m.model_fields["op"].annotation)[0] for m in get_args(union))


PREDICATE_OPS = _ops()


class Rule(_Strict):
    id: str
    action: Literal["deny"]
    reason: str
    all_of: Annotated[List[Predicate], Field(min_length=1, max_length=8)]

    @field_validator("id")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9-]{3,48}$", v):
            raise ValueError(f"rule id must be a lowercase slug: {v!r}")
        return v


class Policy(_Strict):
    version: str
    parent: Optional[str] = None
    rules: Annotated[List[Rule], Field(min_length=1, max_length=32)]

    @field_validator("version", "parent")
    @classmethod
    def _version(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.match(r"^v\d+[a-z-]*$", v):
            raise ValueError(f"version must look like v4: {v!r}")
        return v

    @field_validator("rules")
    @classmethod
    def _unique_ids(cls, rules: List[Rule]) -> List[Rule]:
        ids = [r.id for r in rules]
        if len(set(ids)) != len(ids):
            raise ValueError("rule ids must be unique within a policy")
        return rules


def parse(raw: Union[str, bytes, dict]) -> Policy:
    """Parse a candidate. Raises pydantic.ValidationError naming what was wrong."""
    if isinstance(raw, (str, bytes)):
        raw = json.loads(raw)
    return Policy.model_validate(raw)


def canonical_json(policy: Policy) -> str:
    """Byte-stable serialization. The chain hashes this, so key order is fixed."""
    return json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def load(path: str) -> Policy:
    with open(path, "rb") as fh:
        return parse(fh.read())
