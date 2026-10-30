from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend import auth, netguard
from backend.approvals import ApprovalNotPending, ApprovalStore, InMemoryApprovalStore, PendingApproval
from backend.approvals.flow import GRANTED, REFUSED, WAITING, queue_for_approval
from backend.config import settings
from backend.events.bus import EventBus
from backend.events.models import AgentActivityEvent, ApprovalEvent, StatusEvent
from backend.guardian.middleware import Guardian
from backend.guardian.schema import CheckRequest, RequestError, ToolCall, to_tool_call
from backend.guardian.taxonomy import taxonomy_payload
from backend.policy import engine as policy_engine
from backend.policy.loader import PolicyError, PolicyStore, resolve_policy_path
from backend.targets import session_store
from backend.tap.client import observe_agent, ACTIONABLE_EVENTS
from backend.tap.extract import extract_tool_calls, has_content, synthetic_event_call
from backend.usage_logger import log_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail at startup, not on the first request, if the policy file or the key
    # configuration is broken.
    _policy_store()
    _api_keys()
    _approver_keys()
    store = InMemoryApprovalStore()
    store.add_listener(_on_approval_change)
    app.state.approvals = store
    try:
        yield
    finally:
        await store.close()


app = FastAPI(title="GuardianAI - Real-Time Agent Defense Monitor", lifespan=lifespan)

# Outbound hooks. Tests replace these to run offline: the resolver maps hostnames
# to addresses, and the transport answers the verify health check.
app.state.resolver = netguard.system_resolve
app.state.verify_transport = None
app.state.policy_store = None
app.state.approvals = None


def _approvals() -> ApprovalStore:
    store = getattr(app.state, "approvals", None)
    if store is None:
        store = InMemoryApprovalStore()
        store.add_listener(_on_approval_change)
        app.state.approvals = store
    return store


async def _on_approval_change(approval: PendingApproval, change: str) -> None:
    """Show every approval state change on the session's dashboard."""
    d = approval.to_dict()
    await _get_session(approval.session)["bus"].emit(ApprovalEvent(
        change=change,
        approval_id=approval.id,
        status=approval.status,
        reason=approval.reason,
        note=approval.note,
        tool_name=approval.tool,
        server=approval.server,
        agent=approval.agent,
        policy_rule_id=approval.rule_id,
        decision_id=approval.decision_id,
        arguments_sha256=approval.arguments_sha256,
        arguments=approval.arguments_preview,
        diff_from=approval.diff_from,
        diff=approval.diff,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        resolved_at=approval.resolved_at,
        resolved_by=approval.resolved_by,
        grant_valid_until=d["grant_valid_until"],
        uses=approval.uses,
    ))


def _policy_store() -> PolicyStore:
    """The policy store for the configured file (recreated if the setting changes)."""
    store = getattr(app.state, "policy_store", None)
    wanted = resolve_policy_path(settings.guardian_policy_file)
    if store is None or store.path != wanted:
        store = PolicyStore(wanted)
        app.state.policy_store = store
    return store


def _api_keys() -> dict[str, str]:
    return auth.parse_keys(settings.guardian_api_keys, env_name="GUARDIAN_API_KEYS")


def _approver_keys() -> dict[str, str]:
    return auth.parse_keys(settings.guardian_approver_keys, env_name="GUARDIAN_APPROVER_KEYS")


def _client_sid(value: str | None) -> str:
    """A session id chosen by the client. The app: namespace belongs to API keys."""
    sid = value or "default"
    if sid.startswith(auth.APP_SESSION_PREFIX):
        raise HTTPException(status_code=400, detail="Session ids starting with 'app:' are reserved for API-key callers")
    if len(sid) > 200:
        raise HTTPException(status_code=400, detail="Session id too long")
    return sid

# Per-session state: event bus, guardian, observer tasks
_sessions: dict[str, dict] = {}

# Cap on live sessions (ids come from unauthenticated X-Session-Id / ?session= values:
# without a cap, a client could grow memory by sending endless new ids). At the cap the
# least recently used session is evicted, preferring one with no subscribers or observers.
MAX_SESSIONS = 1000

SKIP_EVENTS = {
    "decomposition_start", "synthesis_start", "wave_start", "subtask_start",
    "token", "ping", "pong", "heartbeat",
}


def _evict_session() -> None:
    """Drop one session to make room: the least recently used idle one, else the LRU."""
    victim = None
    for sid, sess in _sessions.items():  # dict order is least to most recently used
        idle = sess["bus"].subscriber_count == 0 and not any(
            not t.done() for t in sess["observers"].values()
        )
        if idle:
            victim = sid
            break
    if victim is None:
        victim = next(iter(_sessions))
    for task in _sessions[victim]["observers"].values():
        task.cancel()
    del _sessions[victim]
    logger.info("Evicted session %s (cap %d)", victim[:8], MAX_SESSIONS)


def _get_session(session_id: str) -> dict:
    """Get or create per-session state (event bus, guardian, observer tasks).

    Every access marks the session most recently used; creating one at the cap
    evicts the least recently used session instead of refusing.
    """
    if session_id in _sessions:
        _sessions[session_id] = _sessions.pop(session_id)  # move to the MRU end
    else:
        while len(_sessions) >= MAX_SESSIONS:
            _evict_session()
        bus = EventBus()
        _sessions[session_id] = {
            "bus": bus,
            "guardian": Guardian(event_bus=bus),
            "observers": {},  # {name: asyncio.Task}
        }
    return _sessions[session_id]


def _summarize_event(event: dict) -> str:
    event_type = event.get("type", "unknown")
    data = event.get("data", {})
    summaries = {
        "query_received": lambda d: f"Query: {d.get('query', '')[:120]}",
        "decomposition_result": lambda d: f"Classified as {d.get('complexity', '?').upper()}",
        "agent_start": lambda d: f"Agent [{d.get('agent', d.get('name', '?')).upper()}] activated",
        "docs_fetched": lambda d: f"Fetched {d.get('services', 0)} docs ({d.get('chars', 0)} chars)",
        "planner_output": lambda d: f"Plan ready: {d.get('criteria_count', '?')} criteria",
        "generator_output": lambda d: f"Output generated (iter {d.get('iteration', 1)})",
        "evaluation": lambda d: f"Score {d.get('score', '?')}/10 ({'PASS' if d.get('passed') else 'FAIL'})",
        "subtask_complete": lambda d: f"Subtask done, score {d.get('score', '?')}",
        "synthesis_complete": lambda d: f"Synthesis done (coherence: {d.get('coherence_score', '?')}/10)",
        "validation_result": lambda d: f"{'VALID' if d.get('valid') else 'INVALID'}, {d.get('service_count', 0)} services",
        "plan": lambda d: f"Plan: {d.get('destination', {}).get('name', '?')}",
        "agent_result": lambda d: "Agent result received",
        "synthesis": lambda d: "Final synthesis ready",
        "complete": lambda d: "Pipeline complete",
        "error": lambda d: f"Error: {d.get('message', 'unknown')}",
    }
    fn = summaries.get(event_type, lambda d: event_type)
    try:
        return fn(data)
    except Exception:
        return event_type


def _make_event_handler(session_id: str):
    """Create an event handler bound to a specific session."""
    session = _get_session(session_id)
    bus = session["bus"]
    guardian = session["guardian"]

    async def on_agent_event(app_name: str, event: dict):
        event_type = event.get("type", "unknown")
        if not isinstance(event_type, str):
            event_type = "unknown"
        raw_data = event.get("data")
        data = raw_data if isinstance(raw_data, dict) else {}
        elapsed = event.get("elapsed", 0)
        if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool):
            elapsed = 0

        if event_type in SKIP_EVENTS:
            return

        agent = data.get("agent", data.get("name", ""))
        task_id = data.get("task_id", data.get("id", ""))
        await bus.emit(
            AgentActivityEvent(
                event_type=event_type,
                elapsed=elapsed,
                agent=agent if isinstance(agent, str) else str(agent),
                task_id=task_id if isinstance(task_id, str) else str(task_id),
                summary=_summarize_event(event),
                data={**data, "_source": app_name},
                known_type=event_type in ACTIONABLE_EVENTS,
            )
        )

        # Every event is evaluated, whatever its type. Tool-call shapes become
        # tool calls; the rest of the event is checked as guardian.event.<type>.
        calls, remainder = extract_tool_calls(event, app_name=app_name)
        if not calls or has_content(remainder):
            calls.append(synthetic_event_call(event, remainder, app_name=app_name))
        try:
            loaded = _policy_store().get()
        except PolicyError as exc:
            logger.error("No policy available, observed event not evaluated: %s", exc)
            return
        for call in calls:
            decision = policy_engine.evaluate(loaded, call, block_threshold=settings.block_threshold)
            # The tap cannot stop anything: record what the policy would have done.
            decision.enforced = False
            await guardian.record(decision, call, source=app_name, observed=True)
            for match in decision.matches:
                asyncio.create_task(log_event(
                    "threat_flagged",
                    session_id=session_id,
                    app_name=app_name,
                    rule_name=match.rule_name,
                    owasp_id=match.owasp_llm,
                    threat_level=match.threat_level.value,
                    reason=match.reason,
                    total_events_checked=guardian._total_checked,
                    total_blocked=guardian._total_blocked,
                ))

    return on_agent_event


def _start_observer(session_id: str, name: str, ws_url: str) -> None:
    """Start an observer task for a target app within a session."""
    session = _get_session(session_id)
    observers = session["observers"]
    bus = session["bus"]

    if name in observers and not observers[name].done():
        return

    on_event = _make_event_handler(session_id)

    async def on_connect(app_name: str):
        session_store.set_status(session_id, app_name, "connected")
        await bus.emit(StatusEvent(status="target_connected", message=f"{app_name} connected"))
        asyncio.create_task(log_event("app_connected", session_id=session_id, app_name=app_name))

    async def on_disconnect(app_name: str):
        session_store.set_status(session_id, app_name, "disconnected")
        await bus.emit(StatusEvent(status="target_disconnected", message=f"{app_name} disconnected"))
        asyncio.create_task(log_event("app_disconnected", session_id=session_id, app_name=app_name))

    async def on_reject(app_name: str, message: str):
        session_store.set_status(session_id, app_name, "rejected")
        await bus.emit(StatusEvent(status="target_rejected", message=f"{app_name}: {message}"))

    async def _observe():
        session_store.set_status(session_id, name, "connecting")
        await observe_agent(
            name, ws_url, on_event, on_connect, on_disconnect,
            allow_private=settings.allow_private_targets,
            resolver=app.state.resolver,
            on_reject=on_reject,
        )

    observers[name] = asyncio.create_task(_observe())
    logger.info("[session=%s] Observer started for %s", session_id[:8], name)


def _stop_observer(session_id: str, name: str) -> None:
    session = _get_session(session_id)
    observers = session["observers"]
    if name in observers:
        observers[name].cancel()
        del observers[name]
        session_store.set_status(session_id, name, "disconnected")
        logger.info("[session=%s] Observer stopped for %s", session_id[:8], name)


def _start_all_observers(session_id: str) -> None:
    """Start observers for all targets in a session."""
    for target in session_store.list_all(session_id):
        _start_observer(session_id, target.name, target.ws_url)


# ---- API (all session-scoped via X-Session-Id header) ----

class AddTargetRequest(BaseModel):
    name: str
    ws_url: str


@app.post("/api/targets")
async def add_target(req: AddTargetRequest, x_session_id: str | None = Header(None)):
    sid = _client_sid(x_session_id)
    if session_store.get(sid, req.name):
        return JSONResponse({"error": f"Target '{req.name}' already exists"}, status_code=409)
    try:
        await netguard.check_target_url(
            req.ws_url, allow_private=settings.allow_private_targets, resolver=app.state.resolver,
        )
    except netguard.TargetRejected as exc:
        return JSONResponse({"error": exc.message, "code": exc.code}, status_code=400)
    target = session_store.add(sid, req.name, req.ws_url)
    _start_observer(sid, target.name, target.ws_url)
    return {"status": "added", "target": {"name": target.name, "ws_url": target.ws_url}}


@app.delete("/api/targets/{name}")
async def remove_target(name: str, x_session_id: str | None = Header(None)):
    sid = _client_sid(x_session_id)
    _stop_observer(sid, name)
    if session_store.remove(sid, name):
        return {"status": "removed", "name": name}
    return JSONResponse({"error": "Target not found"}, status_code=404)


@app.get("/api/targets")
async def list_targets(x_session_id: str | None = Header(None)):
    sid = _client_sid(x_session_id)
    targets = [
        {"name": t.name, "ws_url": t.ws_url, "status": t.status}
        for t in session_store.list_all(sid)
    ]
    return {"targets": targets}


def _authenticate(request: Request) -> str | None:
    """API-key principal for /api/check, or None when keys are not configured."""
    keys = _api_keys()
    if not keys:
        return None
    name = auth.match_key(auth.bearer_token(request.headers.get("authorization")), keys)
    if name is None:
        raise HTTPException(
            status_code=401, detail="A valid API key is required (Authorization: Bearer <key>)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return name


def _top_label(decision) -> tuple[str, str, str, str]:
    top = decision.top_match
    if top is not None and decision.deciding_detectors:
        return top.rule_name, top.owasp_llm, top.threat_level.value, top.reason
    return "policy", decision.owasp_llm, "high" if decision.effect == "deny" else "medium", decision.reasons[0]


@app.post("/api/check")
async def check_content(req: CheckRequest, request: Request, x_session_id: str | None = Header(None)):
    """Policy decision point for a tool call.

    Send ``{"tool": {"name": ...}, "arguments": {...}, "agent": {...}}``. The
    detectors run over the arguments, then the policy file decides:

    * allow: 200 ``{"effect": "allow", "blocked": false, ...}``
    * deny: 403 ``{"effect": "deny", "blocked": true, "rule_id": ..., "reasons": [...]}``
    * require_approval: 202 ``{"status": "pending", "approval_id", "poll_url"}``.
      The caller must not run the tool yet. Poll ``GET /api/approvals/{id}?wait=30``;
      once it says ``approved``, send the identical call again and it returns
      200 (a single-use grant unless the rule sets ``grant_ttl_seconds``).

    In monitor mode every call gets 200 and ``enforced: false``, with the
    effect the policy would have applied. Legacy ``{"content": ...}`` and
    ``{"event": ...}`` bodies are wrapped as ``guardian.content`` and
    ``guardian.event.<type>`` tool calls.
    """
    principal = _authenticate(request)
    if principal is not None:
        sid = auth.APP_SESSION_PREFIX + principal
    else:
        sid = _client_sid(x_session_id or req.session_id)
    try:
        call = to_tool_call(req)
    except RequestError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    try:
        loaded = _policy_store().get()
    except PolicyError as exc:
        logger.error("Policy unavailable: %s", exc)
        return JSONResponse({"error": "Policy unavailable; refusing to decide", "blocked": True}, status_code=503)

    decision = policy_engine.evaluate(
        loaded, call, principal=principal, block_threshold=settings.block_threshold,
    )
    source = principal or call.agent_name or req.source
    guardian = _get_session(sid)["guardian"]

    if decision.effect == "require_approval" and decision.enforced:
        return await _approval_flow(decision, call, sid=sid, principal=principal, source=source, guardian=guardian)

    await guardian.record(decision, call, source=source)
    return _decision_response(decision, sid=sid, source=source, guardian=guardian)


def _decision_body(decision) -> dict:
    return {
        **decision.to_dict(),
        "threshold": settings.block_threshold,
        "matches": [
            {**m.to_dict(), "blocking": decision.blocked and m.rule_name in decision.deciding_detectors}
            for m in decision.matches
        ],
    }


def _decision_response(decision, *, sid: str, source: str, guardian: Guardian, extra: dict | None = None,
                       status_code: int | None = None) -> JSONResponse:
    body = {**_decision_body(decision), **(extra or {})}
    if decision.blocked and decision.effect == "deny":
        rule_name, owasp_llm, level, reason = _top_label(decision)
        asyncio.create_task(log_event(
            "threat_blocked",
            session_id=sid,
            app_name=source,
            rule_name=rule_name,
            owasp_id=owasp_llm,
            threat_level=level,
            reason=reason,
            total_events_checked=guardian._total_checked,
            total_blocked=guardian._total_blocked,
        ))
    if status_code is None:
        status_code = 403 if decision.blocked else 200
    return JSONResponse(body, status_code=status_code)


def _agent_key(call: ToolCall, principal: str | None) -> str:
    """Who an approval is bound to: the API key name, else the self-reported agent."""
    return principal or call.agent_id or call.agent_name or ""


async def _approval_flow(decision, call: ToolCall, *, sid: str, principal: str | None, source: str,
                         guardian: Guardian) -> JSONResponse:
    """require_approval in enforce mode: reuse a grant, join a pending approval, or open one."""
    outcome = await queue_for_approval(_approvals(), decision, call, session=sid, agent=_agent_key(call, principal))
    approval, sha = outcome.approval, outcome.arguments_sha256

    if outcome.status == GRANTED:
        decision.effect = "allow"
        decision.reasons.append(f"Approved by {approval.resolved_by or 'an approver'} (approval {approval.id})")
        await guardian.record(decision, call, source=source, approval_id=approval.id)
        return _decision_response(decision, sid=sid, source=source, guardian=guardian, extra={
            "status": "approved", "approval_id": approval.id, "arguments_sha256": sha,
            "grant_valid_until": approval.grant_valid_until(),
        })

    if outcome.status == WAITING:
        # Same call retried while a human is still deciding: no second card.
        return _decision_response(decision, sid=sid, source=source, guardian=guardian, status_code=202, extra={
            "status": "pending", "approval_id": approval.id, "poll_url": f"/api/approvals/{approval.id}",
            "expires_at": approval.expires_at, "arguments_sha256": sha,
        })

    if outcome.status == REFUSED:
        decision.effect = "deny"
        decision.reasons.append(outcome.error)
        await guardian.record(decision, call, source=source)
        return _decision_response(decision, sid=sid, source=source, guardian=guardian, status_code=429)

    await guardian.record(decision, call, source=source, approval_id=approval.id)
    return _decision_response(decision, sid=sid, source=source, guardian=guardian, status_code=202, extra={
        "status": "pending", "approval_id": approval.id, "poll_url": f"/api/approvals/{approval.id}",
        "expires_at": approval.expires_at, "arguments_sha256": sha,
    })


# ---- Approvals ----
#
# Who may see and answer an approval:
# * GUARDIAN_APPROVER_KEYS set: answering needs an approver key
#   (Authorization: Bearer). Approver keys may also read any approval.
# * Otherwise, for sessions owned by an API key (app:<name>) nobody can answer,
#   so those approvals time out as denied. An app's own key never approves its
#   own calls.
# * Otherwise (open demo mode) anyone holding the session id may answer. The
#   agent knows its session id too, so in demo mode an agent could approve
#   itself: real deployments need GUARDIAN_APPROVER_KEYS, or SSO in front of
#   these endpoints.


def _approver(request: Request) -> str | None:
    keys = _approver_keys()
    if not keys:
        return None
    return auth.match_key(auth.bearer_token(request.headers.get("authorization")), keys)


def _requester_session(request: Request) -> str | None:
    """The session the caller speaks for: its API key's app session, or X-Session-Id."""
    token = auth.bearer_token(request.headers.get("authorization"))
    keys = _api_keys()
    if keys and token:
        name = auth.match_key(token, keys)
        if name is not None:
            return auth.APP_SESSION_PREFIX + name
    header = request.headers.get("x-session-id")
    if header is not None:
        if header.startswith(auth.APP_SESSION_PREFIX) or len(header) > 200:
            return None
        return header
    return None if keys else "default"


async def _load_approval(approval_id: str, request: Request, *, write: bool) -> tuple[PendingApproval, str]:
    approval = await _approvals().get(approval_id[:100])
    not_found = HTTPException(status_code=404, detail="No such approval")
    if approval is None:
        raise not_found
    approver = _approver(request)
    if write:
        if _approver_keys():
            if approver is None:
                raise HTTPException(status_code=401, detail="An approver key is required",
                                    headers={"WWW-Authenticate": "Bearer"})
            return approval, approver
        if approval.session.startswith(auth.APP_SESSION_PREFIX):
            raise HTTPException(status_code=403,
                                detail="Approvals for API-key sessions need GUARDIAN_APPROVER_KEYS")
        if _requester_session(request) != approval.session:
            raise not_found
        return approval, "session"
    if approver is not None:
        return approval, approver
    if _requester_session(request) != approval.session:
        raise not_found
    return approval, ""


class ApprovalAnswer(BaseModel):
    approve: bool
    note: str = ""


@app.get("/api/approvals")
async def list_approvals(request: Request, status: str | None = None, session: str | None = None):
    """Approvals of the caller's session (newest last). Approver keys may name any ``session``."""
    if session is not None and _approver(request) is not None:
        sid = session[:200]
    else:
        sid = _requester_session(request)
    if sid is None:
        raise HTTPException(status_code=401, detail="Identify the session (X-Session-Id or API key)")
    items = await _approvals().list(session=sid, status=status)
    return {"approvals": [a.to_dict() for a in items]}


@app.get("/api/approvals/{approval_id}")
async def get_approval(approval_id: str, request: Request, wait: float = 0):
    """Approval state. ``?wait=N`` (up to 60 s) holds the request until it is resolved."""
    approval, _ = await _load_approval(approval_id, request, write=False)
    if wait > 0 and approval.status == "pending":
        approval = await _approvals().wait(approval.id, min(float(wait), 60.0)) or approval
    return approval.to_dict()


@app.post("/api/approvals/{approval_id}")
async def answer_approval(approval_id: str, answer: ApprovalAnswer, request: Request):
    approval, by = await _load_approval(approval_id, request, write=True)
    try:
        approval = await _approvals().resolve(approval.id, approve=answer.approve, by=by, note=answer.note)
    except ApprovalNotPending as exc:
        return JSONResponse({"error": str(exc), **approval.to_dict()}, status_code=409)
    return approval.to_dict()


@app.get("/api/policy")
async def policy_info():
    """Which policy is in force: path, hash, mode, rule ids, and any reload error."""
    store = _policy_store()
    loaded = store.get()
    return {
        "path": loaded.path,
        "sha256": loaded.sha256,
        "version": loaded.policy.version,
        "mode": loaded.policy.mode,
        "default_effect": loaded.policy.default_effect,
        "rules": [{"id": r.id, "phase": r.phase, "effect": r.effect, "description": r.description}
                  for r in loaded.policy.rules],
        "reload_error": store.last_error,
    }


@app.get("/api/taxonomy")
async def taxonomy():
    """OWASP LLM Top 10 (2025) and Agentic Top 10 (2026) labels, plus the rule mapping."""
    return taxonomy_payload()


@app.post("/api/targets/verify")
async def verify_target(body: dict):
    """Verify a target app has guardian-tap installed and is reachable.

    The URL comes from an unauthenticated browser, so it is checked before any
    request is made: ws/wss only, every resolved address must be public (unless
    ALLOW_PRIVATE_TARGETS is set), redirects are refused, and both the health
    check and the WebSocket handshake connect to the address that was checked.
    """
    import httpx
    import websockets

    ws_url = body.get("ws_url", "") if isinstance(body, dict) else ""
    if not ws_url or not isinstance(ws_url, str):
        return JSONResponse({"error": "No URL provided"}, status_code=400)

    try:
        target = await netguard.check_target_url(
            ws_url, allow_private=settings.allow_private_targets, resolver=app.state.resolver,
        )
    except netguard.TargetRejected as exc:
        return {"status": "error", "code": exc.code, "message": exc.message}

    request_kwargs: dict = {"headers": {"Host": target.host_header}}
    if target.secure:
        # TLS SNI and certificate verification use the real hostname even
        # though the TCP connection goes to the pinned address.
        request_kwargs["extensions"] = {"sni_hostname": target.host}

    try:
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, trust_env=False,
            transport=app.state.verify_transport,
        ) as client:
            resp = await client.get(target.pinned_http_url(), **request_kwargs)
    except httpx.ConnectError:
        return {"status": "error", "code": "app_unreachable",
                "message": "Cannot reach the app. Check that the URL is correct and the app is deployed."}
    except httpx.TimeoutException:
        return {"status": "error", "code": "app_timeout",
                "message": "The app took too long to respond. It may be starting up. Try again in a minute."}
    except Exception as e:
        return {"status": "error", "code": "connection_error", "message": f"Connection error: {e}"}

    if resp.is_redirect:
        return {"status": "error", "code": "redirect_refused",
                "message": f"The app answered with a redirect (HTTP {resp.status_code}). GuardianAI does not follow "
                           "redirects; register the final URL instead."}

    if resp.status_code == 404:
        return {"status": "error", "code": "guardian_tap_not_installed",
                "message": "The app is running, but guardian-tap is not installed. Make sure you have added 'from guardian_tap import attach_observer; attach_observer(app)' to your server file and redeployed."}

    if resp.status_code != 200:
        return {"status": "error", "code": "unexpected_status",
                "message": f"Got HTTP {resp.status_code} from the app. Expected 200. The app may have a route conflict at /ws-observe."}

    try:
        data = resp.json()
    except Exception:
        return {"status": "error", "code": "invalid_response",
                "message": "The /ws-observe endpoint exists but did not return valid JSON. It may be conflicting with another route in your app."}

    if not isinstance(data, dict) or not data.get("guardian_tap"):
        return {"status": "error", "code": "not_guardian_tap",
                "message": "The /ws-observe endpoint exists but is not a guardian-tap endpoint. It may be conflicting with another route in your app."}

    if not data.get("websocket_support", True):
        return {"status": "error", "code": "no_websocket_support",
                "message": "guardian-tap is installed, but WebSocket support is missing. For Python apps, run: pip install websockets (or add 'websockets' to requirements.txt) and redeploy."}

    try:
        async with websockets.connect(
            target.url, open_timeout=5, host=target.pinned_ip, port=target.port, proxy=None,
        ) as ws:
            await ws.close()
    except Exception as e:
        return {"status": "error", "code": "websocket_failed",
                "message": f"Health check passed but WebSocket connection failed: {e}. This may be a proxy or firewall issue."}

    return {"status": "ok", "code": "ready", "message": "All checks passed. Ready to connect.",
            "details": {"version": data.get("version"), "framework": data.get("framework")}}


# ---- Frontend ----

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
async def index():
    return FileResponse("frontend/index.html")


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()

    # Get session ID from query param. Sessions bound to an API key need that
    # key (or an approver key) as ?token=.
    sid = websocket.query_params.get("session", "default")[:200]
    if sid.startswith(auth.APP_SESSION_PREFIX):
        token = websocket.query_params.get("token")
        owner = sid[len(auth.APP_SESSION_PREFIX):]
        app_key = _api_keys().get(owner)
        ok = (app_key is not None and token is not None and auth.match_key(token, {owner: app_key}) == owner) \
            or auth.match_key(token, _approver_keys()) is not None
        if not ok:
            await websocket.close(code=1008)
            return
    session = _get_session(sid)
    bus = session["bus"]

    # Start observers for this session if not already running
    _start_all_observers(sid)

    # Log session start
    user_agent = dict(websocket.headers).get("user-agent", "")
    ip_address = websocket.client.host if websocket.client else ""
    asyncio.create_task(log_event(
        "session_started", session_id=sid, user_agent=user_agent, ip_address=ip_address,
    ))

    queue = bus.subscribe()
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event.model_dump())
    except WebSocketDisconnect:
        bus.unsubscribe(queue)
    except Exception:
        bus.unsubscribe(queue)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
