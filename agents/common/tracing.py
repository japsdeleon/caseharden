#!/usr/bin/env python3
"""Export the fleet's spans to Cloud Trace, so a chain link can open a real DAG.

Until this existed, every trace id in this project was derived: a SHA-256 over
the session and turn, which is a stable correlation key shared by the conduct
row, the chain link and the finding, and is not a handle Cloud Trace can open.

For two days the deployed fleet recorded trace ids that answered 404. The
provider was installed, the flush ran and returned true, no export was refused,
and nothing arrived. The cause was **the sampler**, not the transport. Cloud Run
puts a W3C traceparent on every inbound request with the sampled flag off, the
default sampler is parent-based and honours that decision, so each request's
spans were created with a valid context and never recorded. The conduct row got
a real trace id for a trace that was never written. `ALWAYS_ON` in `start()` is
the fix, and it is one line.

Two changes made that visible rather than guessable. The startup span below has
no parent, so it was sampled and landed while every request span vanished, which
is what separated "the transport is broken" from "the spans are not recorded".
And `Middleware` opens a span this module owns on every request, so the DAG does
not depend on which tracer provider a library happened to use.

Transport is `v2/projects/{project}/traces:batchWrite`, the Cloud Trace API's own
ingestion path, which answers with a status code this module reads. A refused
write is printed as an ALERT. The earlier attempt sent OTLP to
`telemetry.googleapis.com`; that path is not known to be broken, but it puts a
translation layer between this process and the API, and while the sampler bug was
unsolved that layer was one more thing that could be losing the batch. This is
the shorter path and it is kept.

No new dependency. ADK already emits OpenTelemetry spans, so this is a span
exporter of about forty lines over `urllib`, the same way `caseharden/bq.py`
talks to BigQuery. The alternative was `opentelemetry-exporter-gcp-trace`, a
dependency this image does not have and does not need.

`span_payload` is a pure function on purpose. It holds every rule about the wire
format that is worth getting wrong, and the offline test suite exercises it
without the OpenTelemetry SDK installed, which the CI runner does not have.

Two other pieces make the fan-out one trace rather than five:

  `inject` puts the W3C traceparent on outbound A2A requests, from the Foreman
  to each detector.
  `Middleware` takes it off inbound ones, so a detector's spans are children of
  the investigation that asked for them rather than roots of their own.

Tokens expire, and a Cloud Run service outlives one. The exporter below re-reads
the token per batch from the same place everything else in this repo does, which
is never Application Default Credentials.
"""

from __future__ import annotations

import atexit
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Callable, Optional

TRACE_API = os.environ.get("CASEHARDEN_TRACE_API",
                           "https://cloudtrace.googleapis.com/v2")

# One request per hundred spans. The API takes more, but a request that is
# refused for size loses every span in it, and a fan-out across four detectors
# does not come close to this.
SPANS_PER_CALL = 100

# Cloud Trace's own limits. Exceed one and the whole batch is refused with a 400,
# so they are enforced here rather than discovered in production.
NAME_BYTES = 128
VALUE_BYTES = 256
KEY_BYTES = 128
MAX_ATTRIBUTES = 32

KINDS = {"INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER"}

_provider = None
_flushed = False

# How long a request will wait for its spans to leave the process. Short: this
# is on the response path, and a slow telemetry endpoint must not become a slow
# agent.
FLUSH_MS = int(os.environ.get("CASEHARDEN_FLUSH_MS", "3000"))


def _rfc3339(nanos: int) -> str:
    """Nanoseconds since the epoch, as the API's timestamp format."""
    seconds, remainder = divmod(int(nanos), 1_000_000_000)
    stamp = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{remainder:09d}Z"


def _clip(text: str, limit: int) -> str:
    """The longest prefix of `text` that fits in `limit` UTF-8 bytes.

    Slicing the encoded bytes can land inside a character, and `errors="ignore"`
    then drops that whole character. So the cut has to be measured after the
    decode, not before it, or every count taken from it is wrong.
    """
    raw = str(text).encode("utf-8")
    if len(raw) <= limit:
        return str(text)
    return raw[:limit].decode("utf-8", errors="ignore")


def _truncatable(text: str, limit: int) -> dict:
    """A TruncatableString, counting the bytes dropped rather than hiding them.

    `truncatedByteCount` is what was left out of `value`, not the overshoot
    against the limit. Cutting a four-byte emoji at one byte emits nothing and
    drops four; the difference between the two readings is one byte per split
    character, and the API is told the first.
    """
    raw = str(text).encode("utf-8")
    if len(raw) <= limit:
        return {"value": str(text), "truncatedByteCount": 0}
    kept = _clip(text, limit)
    return {"value": kept, "truncatedByteCount": len(raw) - len(kept.encode("utf-8"))}


def _attribute(value) -> dict:
    """One AttributeValue. bool before int: in Python a bool is an int."""
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    return {"stringValue": _truncatable(value, VALUE_BYTES)}


def span_payload(project: str, trace_id: str, span_id: str,
                 parent_id: Optional[str], name: str, start_ns: int,
                 end_ns: int, attributes: Optional[dict] = None,
                 kind: str = "INTERNAL") -> dict:
    """One span in the shape `traces:batchWrite` accepts.

    Pure, so the wire format is testable with no SDK and no credentials. The
    `name` field is what puts the span in a trace; the API reads the trace id out
    of it and there is no other field carrying it.
    """
    payload = {
        "name": f"projects/{project}/traces/{trace_id}/spans/{span_id}",
        "spanId": span_id,
        "displayName": _truncatable(name, NAME_BYTES),
        "startTime": _rfc3339(start_ns),
        "endTime": _rfc3339(end_ns),
        "spanKind": kind if kind in KINDS else "SPAN_KIND_UNSPECIFIED",
    }
    if parent_id:
        payload["parentSpanId"] = parent_id
    kept: dict = {}
    dropped = 0
    for key, value in (attributes or {}).items():
        if value is None:
            continue
        if len(kept) >= MAX_ATTRIBUTES:
            dropped += 1
            continue
        # Keys are limited in bytes, like values. Two keys that differ only past
        # the limit collapse into one, and writing the second over the first
        # loses an attribute without saying so, which is the failure this whole
        # module exists to make impossible. Count it instead.
        name_key = _clip(key, KEY_BYTES)
        if name_key in kept:
            dropped += 1
            continue
        kept[name_key] = _attribute(value)
    if kept or dropped:
        payload["attributes"] = {"attributeMap": kept,
                                 "droppedAttributesCount": dropped}
    return payload


class BatchWriteExporter:
    """A span exporter onto the Cloud Trace API.

    Duck-typed rather than a subclass of `SpanExporter`: `BatchSpanProcessor`
    calls `export`, `shutdown` and `force_flush` and checks for none of them, and
    subclassing would mean importing the SDK at module scope, which the offline
    test suite cannot do.
    """

    def __init__(self, project: str, token_fn: Callable[[], str]):
        self.project = project
        self.token_fn = token_fn
        self.url = f"{TRACE_API}/projects/{project}/traces:batchWrite"

    def export(self, spans):
        from opentelemetry.sdk.trace.export import SpanExportResult

        payloads = [self._payload(span) for span in spans]
        ok = True
        for start in range(0, len(payloads), SPANS_PER_CALL):
            ok = self._post(payloads[start:start + SPANS_PER_CALL]) and ok
        return SpanExportResult.SUCCESS if ok else SpanExportResult.FAILURE

    def _payload(self, span) -> dict:
        context = span.get_span_context()
        attributes = dict(span.attributes or {})
        # The resource carries service.name, and Cloud Trace has no resource
        # concept, so it rides along as an attribute or the four detectors are
        # indistinguishable in the DAG.
        resource = getattr(span, "resource", None)
        if resource is not None:
            attributes.setdefault("service.name",
                                  (resource.attributes or {}).get("service.name"))
        parent = getattr(span, "parent", None)
        return span_payload(
            self.project,
            format(context.trace_id, "032x"),
            format(context.span_id, "016x"),
            format(parent.span_id, "016x") if parent else None,
            span.name,
            span.start_time,
            span.end_time or span.start_time,
            attributes,
            getattr(getattr(span, "kind", None), "name", "INTERNAL"),
        )

    def _post(self, spans: list) -> bool:
        try:
            # Minting the token is inside the guard on purpose. It shells out to
            # gcloud on a workstation and reads the metadata server in a
            # container, and both can fail; raising here would escape into the
            # batch processor's export thread rather than printing an ALERT.
            request = urllib.request.Request(
                self.url, data=json.dumps({"spans": spans}).encode("utf-8"),
                method="POST",
                headers={"Authorization": "Bearer " + self.token_fn(),
                         "Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=10):
                return True
        except urllib.error.HTTPError as exc:
            # Loud. A refused export must not look like a working one: the
            # symptom is a trace id in a chain link that Cloud Trace answers 404
            # for, and that is the state this module exists to end.
            print(f"ALERT caseharden span export refused: HTTP {exc.code} "
                  f"{exc.read()[:200]!r}", file=sys.stderr, flush=True)
        except Exception as exc:  # noqa: BLE001 - telemetry never blocks enforcement
            print(f"ALERT caseharden span export failed: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return False

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def start(service_name: str, token_fn: Optional[Callable[[], str]] = None,
          project: Optional[str] = None) -> bool:
    """Install the global tracer provider. Returns whether export is on.

    Called once at import by each agent's module. A failure here is printed and
    swallowed: an agent that cannot export telemetry is still an agent that must
    enforce policy, and a fleet that refuses to start because Cloud Trace is
    unreachable is a worse outcome than one whose DAG has a gap. What must never
    happen is a silent claim, so both the failure to start and any refused
    export are printed as ALERT lines.
    """
    global _provider
    if _provider is not None:
        return True
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ALWAYS_ON

        from caseharden import creds

        token_fn = token_fn or creds.access_token
        project = project or creds.PROJECT
        resource = Resource.create({"service.name": service_name})
        # Attach to whatever provider is global rather than insisting on ours.
        # `set_tracer_provider` is a one-shot: if anything in the process set one
        # first, ours is refused with a warning nobody sees, and the spans are
        # then recorded by their provider while we flush ours. That failure is
        # invisible in exactly the way this module must not be, because both
        # providers are the same class and even the flush answers True.
        provider = trace.get_tracer_provider()
        ours = not hasattr(provider, "add_span_processor")
        if ours:
            # ALWAYS_ON, and this is the whole reason the deployed fleet recorded
            # trace ids that answered 404 for two days. Cloud Run's front end puts
            # a W3C traceparent on every inbound request with the sampled flag
            # off. The default sampler is parent-based, so it honours that: the
            # span is created, its context is valid, the conduct row records a
            # real trace id, and the span is never recorded and never exported.
            # Nothing fails. The startup span below always landed, because it has
            # no parent to inherit a decision from, which is what made the two
            # cases distinguishable at last.
            provider = TracerProvider(resource=resource, sampler=ALWAYS_ON)
            trace.set_tracer_provider(provider)
        provider.add_span_processor(
            BatchSpanProcessor(BatchWriteExporter(project, token_fn)))
        _provider = trace.get_tracer_provider()
        if not hasattr(_provider, "force_flush"):
            _provider = provider
        atexit.register(flush)
        # Said out loud, once, at startup. "No ALERT in the logs" is not evidence
        # that export is working; it is equally consistent with the exporter
        # never running, which is the state this line makes distinguishable.
        print(f"caseharden span export ON service={service_name} "
              f"api={TRACE_API} project={project} "
              f"provider={type(_provider).__name__} "
              f"sampler_forced={ours}",
              file=sys.stderr, flush=True)
        if not ours:
            # We attached a processor to somebody else's provider, so we did not
            # choose its sampler. If it is the default parent-based one, every
            # span under Cloud Run's unsampled inbound traceparent is created and
            # never recorded, and this module exports nothing while reporting
            # success. That is precisely the state it took two days to find, so
            # it is named here rather than left to be rediscovered.
            print("ALERT caseharden did not install its own tracer provider, so "
                  "the sampler is not forced. If it is parent-based, an unsampled "
                  "inbound traceparent drops every span and export goes silent.",
                  file=sys.stderr, flush=True)
        # One span of this module's own, at startup, pushed immediately. If the
        # export path is broken, the ALERT is printed before a single request is
        # served rather than being discovered days later as a chain link whose
        # trace id answers 404. The first deployment of this module reported a
        # successful flush and delivered nothing, and this line is what makes
        # that state impossible to reach quietly again.
        with trace.get_tracer("caseharden").start_as_current_span(
                "caseharden.startup", kind=trace.SpanKind.INTERNAL):
            pass
        flush(FLUSH_MS)
        return True
    except Exception as exc:  # noqa: BLE001 - telemetry never blocks enforcement
        print(f"ALERT caseharden could not start span export: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return False


def flush(timeout_ms: int = 15000) -> None:
    """Push what is buffered.

    Called at the end of every request by `Middleware`, and again at exit. Both
    are needed: Cloud Run freezes the container's CPU between requests, so the
    batch processor's own thread does not get to run, and every service here
    runs with --min-instances=0 so the instance is reclaimed with the batch
    still in it.
    """
    global _flushed
    if _provider is not None:
        try:
            done = _provider.force_flush(timeout_ms)
        except Exception as exc:  # noqa: BLE001
            print(f"ALERT caseharden span flush failed: {type(exc).__name__}: {exc}",
                  file=sys.stderr, flush=True)
            return
        if not _flushed:
            _flushed = True
            print(f"caseharden first span flush returned {done}",
                  file=sys.stderr, flush=True)


def inject(headers: dict) -> dict:
    """Put the current span's traceparent onto an outbound request."""
    try:
        from opentelemetry.propagate import inject as _inject

        _inject(headers)
    except Exception:
        pass
    return headers


class Middleware:
    """ASGI middleware: continue the caller's trace instead of starting a new one.

    Without this each detector's spans are a separate trace and the fan-out is
    four unrelated pictures. The A2A hop carries a W3C traceparent header; this
    reads it and attaches the context for the duration of the request.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        # Setup only. Nothing below this block may call the application, because
        # the fallback at the end of it calls the application itself: if the app
        # were invoked inside a guard that also retries, an exception raised
        # after the response had begun would run the whole request a second time.
        # In this fleet that request writes a conduct event and may take a tool
        # call, so a silent second invocation is not a telemetry bug.
        try:
            from opentelemetry import context as otel_context
            from opentelemetry import trace
            from opentelemetry.propagate import extract

            # HTTP header bytes are latin-1 by specification. Decoding as UTF-8
            # raises on a header this process did not write, and the only effect
            # of that here would be to turn tracing off for the request.
            carrier = {k.decode("latin-1"): v.decode("latin-1")
                       for k, v in scope.get("headers", [])}
            token = otel_context.attach(extract(carrier))
            name = f"{scope.get('method', 'HTTP')} {scope.get('path', '/')}"
            tracer = trace.get_tracer("caseharden")
            kind = trace.SpanKind.SERVER
        except Exception:  # noqa: BLE001 - telemetry never blocks enforcement
            return await self.app(scope, receive, send)

        try:
            # One span this module owns, per request. Everything ADK records
            # hangs under it, and its existence does not depend on which tracer
            # provider a library decided to use: the first deployment of this
            # module exported nothing while reporting success, and a span opened
            # here is the one thing that cannot happen silently.
            with tracer.start_as_current_span(name, kind=kind):
                return await self.app(scope, receive, send)
        finally:
            otel_context.detach(token)
            # Flush here, per request, rather than trusting the batch processor's
            # background thread. Cloud Run throttles a container's CPU to nearly
            # nothing between requests, so that thread does not run once the
            # response is sent and the batch is still sitting in memory when the
            # instance is frozen or reclaimed. The symptom is exactly the one this
            # module exists to end: trace ids written into conduct rows and chain
            # links that Cloud Trace answers 404 for. Measured, not assumed: eight
            # traces existed in the project and none of them were ours.
            flush(FLUSH_MS)
