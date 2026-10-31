"""OpenTelemetry tracing for GuardianAI decisions.

Every tool-call check becomes a span that joins the caller's trace:

* ``POST /api/check`` reads a W3C ``traceparent`` (and ``tracestate``) from
  the request headers, or from ``trace_context`` in the body when the headers
  carry none. The span is named ``execute_tool {tool}``. When the caller says
  it already has its own tool span (``trace_context.tool_span: true``),
  GuardianAI records a child span named ``guardian.check`` instead, so the
  tool is not counted twice.
* The MCP gateway does the same for every ``tools/call``. Trace context
  arrives in the request's ``_meta`` (the MCP SDK extracts it into its own
  server span, which becomes the parent).
* Each approval state change (pending, approved, denied, used) is its own
  short span, parented on the check that opened the approval and tagged with
  ``guardian.approval.id``.

Attributes follow the OpenTelemetry GenAI semantic conventions
(``gen_ai.operation.name``, ``gen_ai.tool.name``, ``gen_ai.tool.call.id``,
``gen_ai.agent.name``) plus GuardianAI's own under ``guardian.*``. Those
conventions are still marked Development, so the names used here are pinned to
one version (``SEMCONV_VERSION``).

Tool arguments are not recorded unless ``GUARDIAN_OTEL_CAPTURE_ARGUMENTS`` is
true, following the conventions' opt-in guidance for
``gen_ai.tool.call.arguments``. Decision reasons are never recorded, because
they can quote argument text.

Export is off unless ``OTEL_EXPORTER_OTLP_ENDPOINT`` (or
``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT``) is set. Without it the OpenTelemetry
API's no-op tracer is used: nothing is recorded or sent. With it, spans go out
over OTLP/HTTP (protobuf), batched.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import threading
from collections import OrderedDict
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import Any, AsyncIterator, Iterator, Mapping

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.trace import Link, NonRecordingSpan, Span, SpanContext, SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger(__name__)

# The GenAI conventions moved out of the main semantic-conventions repository
# and are still marked Development. The attribute names below are the ones in
# opentelemetry-semantic-conventions 0.66b2, schema 1.44.0; a test checks they
# still match that package.
SEMCONV_VERSION = "1.44.0"
SCHEMA_URL = f"https://opentelemetry.io/schemas/{SEMCONV_VERSION}"

GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"
GEN_AI_TOOL_CALL_ARGUMENTS = "gen_ai.tool.call.arguments"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"
GEN_AI_AGENT_ID = "gen_ai.agent.id"
EXECUTE_TOOL = "execute_tool"

CAPTURE_ENV = "GUARDIAN_OTEL_CAPTURE_ARGUMENTS"
MAX_CAPTURED_CHARS = 8192
MAX_TRACKED_APPROVALS = 10_000
TRACER_NAME = "guardian-ai"

_W3C = TraceContextTextMapPropagator()


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def capture_arguments_from_env() -> bool:
    return _truthy(os.environ.get(CAPTURE_ENV))


def _clean(attrs: Mapping[str, Any]) -> dict[str, Any]:
    """Drop empty values: OpenTelemetry attributes cannot be None."""
    out: dict[str, Any] = {}
    for key, value in attrs.items():
        if value is None or value == "" or value == []:
            continue
        out[key] = value
    return out


def _extract(carrier: Mapping[str, Any] | None) -> otel_context.Context | None:
    """W3C trace context from a header-like mapping; None when absent or invalid."""
    if not carrier:
        return None
    flat = {str(k).lower(): v for k, v in carrier.items() if isinstance(v, str)}
    if "traceparent" not in flat:
        return None
    getlist = getattr(carrier, "getlist", None)  # HTTP headers can repeat
    if callable(getlist):
        if len(getlist("traceparent")) > 1:
            return None  # W3C: more than one traceparent is invalid
        states = [v for v in getlist("tracestate") if v.strip()]
        if states:
            flat["tracestate"] = ",".join(states)  # W3C: repeated tracestate headers combine
    try:
        ctx = _W3C.extract(flat)
    except (ValueError, TypeError):
        return None
    if not trace.get_current_span(ctx).get_span_context().is_valid:
        return None
    return ctx


def _meta_carrier(meta: Any) -> dict[str, Any]:
    if meta is None:
        return {}
    if isinstance(meta, Mapping):
        return dict(meta)
    dump = getattr(meta, "model_dump", None)
    if callable(dump):
        try:
            return dict(dump(by_alias=True, exclude_none=True))
        except Exception:
            return {}
    return {}


def _effect_attrs(decision: Any, prefix: str = "guardian") -> dict[str, Any]:
    return _clean({
        f"{prefix}.decision": decision.effect,
        f"{prefix}.decision.id": decision.decision_id,
        f"{prefix}.decision.enforced": bool(decision.enforced),
        f"{prefix}.policy.rule_id": decision.rule_id,
        f"{prefix}.policy.mode": decision.mode,
        f"{prefix}.owasp.llm": decision.owasp_llm,
        f"{prefix}.owasp.agentic": decision.owasp_agentic,
        f"{prefix}.detectors": list(decision.matched_detectors or []),
    })


class CheckSpan:
    """Handle for one /api/check span: set the outcome once it is known."""

    def __init__(self, telemetry: "Telemetry", span: Span) -> None:
        self._telemetry = telemetry
        self.span = span

    def decided(self, decision: Any, *, call: Any = None, approval_id: str = "", approval_status: str = "",
                status_code: int | None = None) -> None:
        attrs = _effect_attrs(decision)
        attrs.update(_clean({
            "guardian.policy.version": getattr(decision, "policy_version", ""),
            "guardian.approval.id": approval_id,
            "guardian.approval.status": approval_status,
            "http.response.status_code": status_code,
        }))
        self.span.set_attributes(attrs)
        if call is not None:
            self._telemetry._maybe_capture(self.span, call)

    @property
    def trace_id(self) -> str:
        sc = self.span.get_span_context()
        return format(sc.trace_id, "032x") if sc.is_valid else ""


class GatewaySpan:
    """Handle for one gateway tools/call span (``update`` takes a GatewayResult)."""

    def __init__(self, span: Span) -> None:
        self.span = span

    def update(self, outcome: Any) -> None:
        decision = getattr(outcome, "decision", None)
        if decision is not None:
            self.span.set_attributes(_effect_attrs(decision))
            self.span.set_attributes(_clean({"guardian.policy.version": getattr(decision, "policy_version", "")}))
        result = getattr(outcome, "result_decision", None)
        if result is not None:
            self.span.set_attributes(_clean({
                "guardian.result.decision": result.effect,
                "guardian.result.decision.id": result.decision_id,
                "guardian.result.policy.rule_id": result.rule_id,
                "guardian.result.detectors": list(result.matched_detectors or []),
            }))
        approval_id = getattr(outcome, "approval_id", "")
        if approval_id:
            self.span.set_attribute("guardian.approval.id", approval_id)
        via = (getattr(outcome, "extra", None) or {}).get("approved_via")
        if via:
            self.span.set_attribute("guardian.approval.via", str(via))


_active_gateway_span: ContextVar[Span | None] = ContextVar("guardian_gateway_span", default=None)


class Telemetry:
    """Creates GuardianAI spans on one tracer provider.

    With no provider argument it uses the global provider, which is the API's
    no-op provider unless ``setup_from_env`` installed an exporting one.
    """

    def __init__(self, tracer_provider: Any = None, *, capture_arguments: bool | None = None) -> None:
        provider = tracer_provider if tracer_provider is not None else trace.get_tracer_provider()
        self.tracer = provider.get_tracer(TRACER_NAME, _package_version(), schema_url=SCHEMA_URL)
        self.capture_arguments = capture_arguments_from_env() if capture_arguments is None else capture_arguments
        self._origins: OrderedDict[str, SpanContext] = OrderedDict()
        self._origins_lock = threading.Lock()

    # ---- helpers -----------------------------------------------------------

    def _maybe_capture(self, span: Span, call: Any) -> None:
        if not self.capture_arguments:
            return
        try:
            text = json.dumps(call.arguments, sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(call.arguments)
        if len(text) > MAX_CAPTURED_CHARS:
            text = text[:MAX_CAPTURED_CHARS] + "...(truncated)"
        span.set_attribute(GEN_AI_TOOL_CALL_ARGUMENTS, text)

    @staticmethod
    def _call_attrs(call: Any, *, tool_name: str | None = None, agent_name: str = "") -> dict[str, Any]:
        return _clean({
            GEN_AI_TOOL_NAME: tool_name or call.name,
            GEN_AI_TOOL_CALL_ID: call.call_id,
            # The authenticated principal, when there is one; the self-reported
            # name only otherwise (it is a label, not an identity).
            GEN_AI_AGENT_NAME: agent_name or call.agent_name,
            "guardian.agent.claimed_name": call.agent_name if agent_name and call.agent_name != agent_name else "",
            GEN_AI_AGENT_ID: call.agent_id,
            "guardian.tool.server": call.server,
        })

    # ---- /api/check ----------------------------------------------------------

    @contextmanager
    def check_span(self, call: Any, *, headers: Mapping[str, Any] | None = None, trace_context: Any = None,
                   principal: str | None = None) -> Iterator[CheckSpan]:
        """Span for one /api/check decision, current for the duration of the block."""
        parent = _extract(headers)
        if parent is None and trace_context is not None:
            parent = _extract({"traceparent": getattr(trace_context, "traceparent", None),
                               "tracestate": getattr(trace_context, "tracestate", None)})
        nested = bool(getattr(trace_context, "tool_span", False))
        attrs = self._call_attrs(call, agent_name=principal or "")
        if nested:
            name = "guardian.check"
        else:
            name = f"{EXECUTE_TOOL} {call.name}"
            attrs[GEN_AI_OPERATION_NAME] = EXECUTE_TOOL
        with self.tracer.start_as_current_span(name, context=parent, kind=SpanKind.INTERNAL, attributes=attrs,
                                               record_exception=False, set_status_on_exception=False) as span:
            with _error_type_only(span):
                yield CheckSpan(self, span)

    # ---- approvals -----------------------------------------------------------

    def watch_approvals(self, store: Any) -> None:
        """Emit a span on every state change of ``store`` (once per store)."""
        watched = getattr(store, "_guardian_telemetry_watchers", None)
        if watched is None:
            watched = set()
            try:
                store._guardian_telemetry_watchers = watched
            except AttributeError:
                pass
        if id(self) in watched:
            return
        watched.add(id(self))
        store.add_listener(self.on_approval_change)

    def _remember_origin(self, approval_id: str, sc: SpanContext) -> None:
        with self._origins_lock:
            self._origins[approval_id] = sc
            self._origins.move_to_end(approval_id)
            while len(self._origins) > MAX_TRACKED_APPROVALS:
                self._origins.popitem(last=False)

    def _origin(self, approval_id: str) -> SpanContext | None:
        with self._origins_lock:
            return self._origins.get(approval_id)

    async def on_approval_change(self, approval: Any, change: str) -> None:
        current = trace.get_current_span().get_span_context()
        origin = self._origin(approval.id)
        if change == "pending" and current.is_valid:
            # Opened inside the check that asked for it: that span is current.
            self._remember_origin(approval.id, current)
            origin = current
        if origin is not None:
            parent = trace.set_span_in_context(NonRecordingSpan(origin))
            links = [Link(current)] if current.is_valid and current != origin else []
        else:
            parent, links = None, []
        attrs = _clean({
            "guardian.approval.id": approval.id,
            "guardian.approval.change": change,
            "guardian.approval.status": approval.status,
            "guardian.approval.reason": approval.reason if change != "pending" else "",
            "guardian.approval.resolved_by": approval.resolved_by,
            "guardian.approval.uses": approval.uses if change == "used" else None,
            "guardian.decision.id": approval.decision_id,
            "guardian.policy.rule_id": approval.rule_id,
            "guardian.tool.server": approval.server,
            GEN_AI_TOOL_NAME: approval.tool,
        })
        span = self.tracer.start_span(f"guardian.approval {change}", context=parent, kind=SpanKind.INTERNAL,
                                      attributes=attrs, links=links)
        span.end()
        if change == "denied":
            with self._origins_lock:
                self._origins.pop(approval.id, None)

    # ---- MCP gateway -----------------------------------------------------------

    @asynccontextmanager
    async def gateway_call(self, name: str, ctx: Any, *, agent_name: str = "") -> AsyncIterator[GatewaySpan]:
        """Span for one gateway tools/call. ``update`` it with the GatewayResult."""
        if trace.get_current_span().get_span_context().is_valid:
            parent = None  # the MCP SDK's server span, already parented on the client's _meta
        else:
            parent = _extract(_meta_carrier(getattr(ctx, "meta", None)))
        request_id = getattr(ctx, "request_id", None)
        attrs = _clean({
            GEN_AI_OPERATION_NAME: EXECUTE_TOOL,
            GEN_AI_TOOL_NAME: name,
            GEN_AI_TOOL_CALL_ID: str(request_id) if request_id is not None else "",
            GEN_AI_AGENT_NAME: agent_name,
        })
        with self.tracer.start_as_current_span(f"{EXECUTE_TOOL} {name}", context=parent, kind=SpanKind.INTERNAL,
                                               attributes=attrs, record_exception=False,
                                               set_status_on_exception=False) as span:
            token = _active_gateway_span.set(span)
            try:
                with _error_type_only(span):
                    yield GatewaySpan(span)
            finally:
                _active_gateway_span.reset(token)

    def decision(self, decision: Any, call: Any, *, approval_id: str = "", definition: bool = False) -> None:
        """A decision the gateway recorded. A decision on the call being made
        becomes an event on its tools/call span. A tool definition screened
        while listing tools gets a span of its own (a child of the current
        tools/call span when a call triggered the refresh), so it is never
        mistaken for a decision on that call."""
        attrs = _effect_attrs(decision)
        attrs["guardian.phase"] = decision.phase
        if approval_id:
            attrs["guardian.approval.id"] = approval_id
        span = None if definition else _active_gateway_span.get()
        if span is not None and span.is_recording():
            span.add_event("guardian.decision", attributes=attrs)
            if decision.phase == "call":
                self._maybe_capture(span, call)
            return
        attrs.update(self._call_attrs(call))
        own = self.tracer.start_span(f"guardian.tool_definition {call.name}", kind=SpanKind.INTERNAL,
                                     attributes=attrs)
        own.end()


@contextmanager
def _error_type_only(span: Span) -> Iterator[None]:
    """Mark the span as failed on an exception, recording only its type.

    The SDK default records the exception message and stack, and those can
    carry tool arguments, which spans otherwise never hold (see
    GUARDIAN_OTEL_CAPTURE_ARGUMENTS).
    """
    try:
        yield
    except BaseException as exc:
        kind = type(exc).__qualname__
        span.set_attribute("error.type", kind)
        span.set_status(Status(StatusCode.ERROR, kind))
        raise


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("guardian-ai")
    except Exception:
        return ""


# ---- process-wide setup ------------------------------------------------------

_lock = threading.Lock()
_provider: Any = None
_telemetry: Telemetry | None = None


def exporter_endpoint() -> str:
    return (os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
            or "").strip()


def setup_from_env() -> bool:
    """Install an OTLP-exporting tracer provider when an endpoint is configured.

    Returns True when exporting. Safe to call more than once. Without an
    endpoint, or with ``OTEL_SDK_DISABLED=true``, nothing is installed and the
    no-op tracer stays in place.
    """
    global _provider, _telemetry
    with _lock:
        if _provider is not None:
            return True
        if not exporter_endpoint() or _truthy(os.environ.get("OTEL_SDK_DISABLED")):
            return False
        protocol = (os.environ.get("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
                    or os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL") or "http/protobuf").strip()
        if protocol != "http/protobuf":
            raise ValueError(f"OTEL_EXPORTER_OTLP_PROTOCOL={protocol!r} is not supported; "
                             "GuardianAI exports OTLP over http/protobuf (port 4318)")
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        base = {} if os.environ.get("OTEL_SERVICE_NAME") else {SERVICE_NAME: "guardian-ai"}
        provider = TracerProvider(resource=Resource.create(base))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)  # the MCP SDK's own spans use the global provider
        atexit.register(provider.shutdown)
        _provider = provider
        _telemetry = None  # rebuilt on the new provider
        logger.info("OpenTelemetry: exporting traces to %s", exporter_endpoint())
        return True


def get_telemetry() -> Telemetry:
    """The process-wide Telemetry (no-op unless ``setup_from_env`` enabled export)."""
    global _telemetry
    with _lock:
        if _telemetry is None:
            _telemetry = Telemetry(_provider)
        return _telemetry


def force_flush(timeout_millis: int = 5000) -> None:
    provider = _provider
    if provider is not None:
        try:
            provider.force_flush(timeout_millis)
        except Exception as exc:
            logger.warning("OpenTelemetry flush failed: %s", type(exc).__name__)
