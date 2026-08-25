#!/usr/bin/env python3
"""Export the fleet's spans to Cloud Trace, so a chain link can open a real DAG.

Until this existed, every trace id in this project was derived: a SHA-256 over
the session and turn, which is a stable correlation key shared by the conduct
row, the chain link and the finding, and is not a handle Cloud Trace can open.

Where this stands, measured rather than claimed. From a workstation the export
works end to end: a span written through this module resolves in Cloud Trace by
its id, under the operator's identity and under workload-sa's. From the deployed
Cloud Run services it does not. The provider is installed and global, the
processor is attached, the per-request flush runs and returns true, no export is
refused, and the trace ids the fleet records still answer 404. Where those spans
go has not been established.

So a deployed conduct row now carries a real span id rather than a derived one,
and that id is still not a handle a reviewer can open. Section 3's sentence about
a link opening the execution DAG, and the trace-DAG beat in the demo script, are
not supported by the deployment today. `100_prove_fleet.py` asserts resolution
and fails on it on purpose: an assertion that passes on an unresolvable id is
how this went unnoticed for a day.

No new dependency. ADK already emits OpenTelemetry spans, and Cloud Trace has an
OTLP endpoint, so the whole job is pointing the OTLP exporter that is already
installed at `telemetry.googleapis.com` with a token on every request. The
alternative was `opentelemetry-exporter-gcp-trace`, which is a dependency this
image does not have and does not need.

Two other pieces make the fan-out one trace rather than five:

  `inject` puts the W3C traceparent on outbound A2A requests, from the Foreman
  to each detector.
  `Middleware` takes it off inbound ones, so a detector's spans are children of
  the investigation that asked for them rather than roots of their own.

An export that is refused is printed as an ALERT rather than swallowed. The
symptom of a silent refusal is a trace id in a chain link that Cloud Trace
answers 404 for, which is the state this module exists to end, and it is
indistinguishable from a working export until somebody opens the link.

Tokens expire, and a Cloud Run service outlives one. The session below re-reads
the token per request from the same place everything else in this repo does,
which is never Application Default Credentials.
"""

from __future__ import annotations

import atexit
import os
import sys
from typing import Callable, Optional

ENDPOINT = os.environ.get("CASEHARDEN_OTLP_ENDPOINT",
                          "https://telemetry.googleapis.com/v1/traces")

_provider = None
_flushed = False

# How long a request will wait for its spans to leave the process. Short: this
# is on the response path, and a slow telemetry endpoint must not become a slow
# agent.
FLUSH_MS = int(os.environ.get("CASEHARDEN_FLUSH_MS", "3000"))


def _session(token_fn: Callable[[], str]):
    """A requests session that carries a fresh bearer token on every export."""
    import requests

    class _Authed(requests.Session):
        def request(self, method, url, **kwargs):  # noqa: D102
            headers = dict(kwargs.pop("headers", None) or {})
            headers["Authorization"] = "Bearer " + token_fn()
            response = super().request(method, url, headers=headers, **kwargs)
            if response.status_code >= 300:
                # Loud. BatchSpanProcessor swallows an export failure into a
                # library log nobody reads, and the symptom is a trace id in a
                # chain link that Cloud Trace answers 404 for: exactly the state
                # this module was written to end. A refused export must not look
                # like a working one.
                print(f"ALERT caseharden span export refused: HTTP "
                      f"{response.status_code} {response.text[:200]}",
                      file=sys.stderr, flush=True)
            return response

    return _Authed()


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
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        from caseharden import creds

        token_fn = token_fn or creds.access_token
        resource = Resource.create({
            "service.name": service_name,
            # Which project the spans belong to. Without it the OTLP endpoint
            # has no way to route them and answers 400.
            "gcp.project_id": project or creds.PROJECT,
        })
        # Attach to whatever provider is global rather than insisting on ours.
        # `set_tracer_provider` is a one-shot: if anything in the process set one
        # first, ours is refused with a warning nobody sees, and the spans are
        # then recorded by their provider while we flush ours. That failure is
        # invisible in exactly the way this module must not be, because both
        # providers are the same class and even the flush answers True.
        provider = trace.get_tracer_provider()
        if not hasattr(provider, "add_span_processor"):
            provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(provider)
        provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(endpoint=ENDPOINT, session=_session(token_fn))))
        _provider = trace.get_tracer_provider()
        if not hasattr(_provider, "force_flush"):
            _provider = provider
        atexit.register(flush)
        # Said out loud, once, at startup. "No ALERT in the logs" is not evidence
        # that export is working; it is equally consistent with the exporter
        # never running, which is the state this line makes distinguishable.
        print(f"caseharden span export ON service={service_name} "
              f"endpoint={ENDPOINT} "
              f"provider={type(_provider).__name__} "
              f"ours={_provider is provider}",
              file=sys.stderr, flush=True)
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
        try:
            from opentelemetry import context as otel_context
            from opentelemetry.propagate import extract

            carrier = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
            token = otel_context.attach(extract(carrier))
            try:
                return await self.app(scope, receive, send)
            finally:
                otel_context.detach(token)
                # Flush here, per request, rather than trusting the batch
                # processor's background thread. Cloud Run throttles a container's
                # CPU to nearly nothing between requests, so that thread does not
                # run once the response is sent and the batch is still sitting in
                # memory when the instance is frozen or reclaimed. The symptom is
                # exactly the one this module exists to end: spans that were
                # recorded, trace ids that were written into conduct rows and
                # chain links, and a Cloud Trace that answers 404 for every one
                # of them. Measured, not assumed: eight traces existed in the
                # project and none of them were ours.
                flush(FLUSH_MS)
        except Exception:
            return await self.app(scope, receive, send)
