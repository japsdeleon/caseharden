#!/usr/bin/env python3
"""The wire format of a Cloud Trace span, checked without the SDK or a project.

The first export path this project used reported success and delivered nothing,
so the rule these tests exist to hold is that a span this module builds is one
the API accepts. Every reason `traces:batchWrite` answers 400 is a rule about
the payload, and each of them is asserted here.

`span_payload` is pure for exactly this reason. The offline runner has neither
OpenTelemetry nor credentials, so the exporter itself cannot be exercised here;
what can be, and what is worth more, is the shape it sends.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from agents.common import tracing  # noqa: E402

PROJECT = "devpost-hackathon-506416"
TRACE = "a" * 32
SPAN = "b" * 16
PARENT = "c" * 16
# 2026-08-26T05:33:09.123456789Z, as nanoseconds since the epoch.
START = 1787722389_123456789
END = START + 250_000_000


def payload(**overrides):
    arguments = dict(project=PROJECT, trace_id=TRACE, span_id=SPAN,
                     parent_id=None, name="handle_ticket", start_ns=START,
                     end_ns=END, attributes=None, kind="SERVER")
    arguments.update(overrides)
    return tracing.span_payload(**arguments)


def test_the_trace_id_travels_in_the_resource_name():
    """There is no other field carrying it. Get this wrong and the span is
    accepted, stored, and belongs to a trace nobody looks at."""
    assert payload()["name"] == f"projects/{PROJECT}/traces/{TRACE}/spans/{SPAN}"


def test_a_root_span_has_no_parent_field():
    """A parentSpanId of "" or null is a 400, not an ignored field."""
    assert "parentSpanId" not in payload()
    assert payload(parent_id=PARENT)["parentSpanId"] == PARENT


def test_timestamps_keep_their_nanoseconds():
    out = payload()
    assert out["startTime"] == "2026-08-26T05:33:09.123456789Z"
    assert out["endTime"] == "2026-08-26T05:33:09.373456789Z"


def test_a_span_that_never_ended_is_still_wellformed():
    """The exporter passes start_ns for end_ns rather than None, because a null
    endTime is refused and losing the span loses the whole batch with it."""
    out = payload(end_ns=START)
    assert out["endTime"] == out["startTime"]


def test_an_unknown_kind_falls_back_rather_than_being_sent():
    assert payload(kind="SERVER")["spanKind"] == "SERVER"
    assert payload(kind="ASGI")["spanKind"] == "SPAN_KIND_UNSPECIFIED"


def test_a_long_display_name_is_truncated_and_says_by_how_much():
    out = payload(name="x" * 200)
    assert out["displayName"]["value"] == "x" * tracing.NAME_BYTES
    assert out["displayName"]["truncatedByteCount"] == 200 - tracing.NAME_BYTES


def test_truncation_counts_bytes_and_not_characters():
    """A multi-byte name near the limit is where a length check written in
    characters sends a payload the API refuses."""
    name = "é" * 100          # 200 bytes, 100 characters
    out = payload(name=name)
    assert len(out["displayName"]["value"].encode()) <= tracing.NAME_BYTES
    assert out["displayName"]["truncatedByteCount"] == 200 - tracing.NAME_BYTES


def test_a_boolean_attribute_is_not_written_as_an_integer():
    """In Python `isinstance(True, int)` is true, so the order of those two
    branches is the whole test. A boolValue sent as intValue is a 400."""
    out = payload(attributes={"attested": True, "turn_index": 3})
    values = out["attributes"]["attributeMap"]
    assert values["attested"] == {"boolValue": True}
    assert values["turn_index"] == {"intValue": "3"}


def test_a_string_attribute_is_truncated_to_the_value_limit():
    out = payload(attributes={"reason": "y" * 400})
    value = out["attributes"]["attributeMap"]["reason"]["stringValue"]
    assert value["value"] == "y" * tracing.VALUE_BYTES
    assert value["truncatedByteCount"] == 400 - tracing.VALUE_BYTES


def test_attributes_are_capped_and_the_drop_is_counted():
    """Over the cap the API refuses the batch. Silently keeping 32 of 40 would
    hide the loss; the count is what makes it visible in the console."""
    out = payload(attributes={f"k{i}": i for i in range(40)})
    assert len(out["attributes"]["attributeMap"]) == tracing.MAX_ATTRIBUTES
    assert out["attributes"]["droppedAttributesCount"] == 40 - tracing.MAX_ATTRIBUTES


def test_a_none_attribute_is_dropped_rather_than_sent_as_null():
    out = payload(attributes={"service.name": None, "policy_version": "v5"})
    assert list(out["attributes"]["attributeMap"]) == ["policy_version"]
    assert out["attributes"]["droppedAttributesCount"] == 0


def test_a_span_with_no_attributes_omits_the_field():
    assert "attributes" not in payload()


@pytest.mark.parametrize("field", ["name", "spanId", "displayName", "startTime",
                                   "endTime", "spanKind"])
def test_every_required_field_is_present(field):
    assert field in payload()
