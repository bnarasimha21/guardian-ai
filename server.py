from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI, Header, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config import settings
from backend.events.bus import EventBus
from backend.events.models import AgentActivityEvent, StatusEvent
from backend.guardian.middleware import Guardian, is_blocking
from backend.targets import session_store
from backend.tap.client import observe_agent, ACTIONABLE_EVENTS
from backend.usage_logger import log_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="GuardianAI - Real-Time Agent Defense Monitor")

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
        data = event.get("data", {})
        elapsed = event.get("elapsed", 0)

        if event_type in SKIP_EVENTS:
            return

        await bus.emit(
            AgentActivityEvent(
                event_type=event_type,
                elapsed=elapsed,
                agent=data.get("agent", data.get("name", "")),
                task_id=data.get("task_id", data.get("id", "")),
                summary=_summarize_event(event),
                data={**data, "_source": app_name},
            )
        )

        if event_type in ACTIONABLE_EVENTS:
            enriched = {**event, "data": {**data, "_source": app_name}}
            matches = await guardian.evaluate(enriched)
            for match in matches:
                asyncio.create_task(log_event(
                    "threat_flagged",
                    session_id=session_id,
                    app_name=app_name,
                    rule_name=match.rule_name,
                    owasp_id=match.owasp_id,
                    threat_level=match.threat_level.value,
                    reason=match.reason,
                    total_events_checked=guardian._total_checked,
                    total_blocked=guardian._total_flagged,
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

    async def _observe():
        session_store.set_status(session_id, name, "connecting")
        await observe_agent(name, ws_url, on_event, on_connect, on_disconnect)

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


def _get_sid(x_session_id: str | None = Header(None)) -> str:
    return x_session_id or "default"


@app.post("/api/targets")
async def add_target(req: AddTargetRequest, x_session_id: str | None = Header(None)):
    sid = x_session_id or "default"
    if session_store.get(sid, req.name):
        return JSONResponse({"error": f"Target '{req.name}' already exists"}, status_code=409)
    target = session_store.add(sid, req.name, req.ws_url)
    _start_observer(sid, target.name, target.ws_url)
    return {"status": "added", "target": {"name": target.name, "ws_url": target.ws_url}}


@app.delete("/api/targets/{name}")
async def remove_target(name: str, x_session_id: str | None = Header(None)):
    sid = x_session_id or "default"
    _stop_observer(sid, name)
    if session_store.remove(sid, name):
        return {"status": "removed", "name": name}
    return JSONResponse({"error": "Target not found"}, status_code=404)


@app.get("/api/targets")
async def list_targets(x_session_id: str | None = Header(None)):
    sid = x_session_id or "default"
    targets = [
        {"name": t.name, "ws_url": t.ws_url, "status": t.status}
        for t in session_store.list_all(sid)
    ]
    return {"targets": targets}


class CheckRequest(BaseModel):
    content: str | None = None
    event: dict | None = None
    source: str = "api-check"


@app.post("/api/check")
async def check_content(req: CheckRequest, x_session_id: str | None = Header(None)):
    """Enforcing check. Returns 200 {"blocked": false} when clean, or 403 with
    {"blocked": true, ...} when a rule at or above BLOCK_THRESHOLD matches.

    The passive tap cannot stop traffic, so apps that want blocking call this
    before acting on content (a tool call, an LLM output, a URL to fetch).
    Pass either `content` (plain text) or `event` ({"type": ..., "data": {...}}).
    """
    if req.event is None and req.content is None:
        return JSONResponse({"error": "Provide 'content' or 'event'"}, status_code=400)
    if req.event is not None:
        ev_type = req.event.get("type", "tool_call")
        ev_data = req.event.get("data")
        if not isinstance(ev_type, str):
            return JSONResponse({"error": "event.type must be a string"}, status_code=400)
        if ev_data is not None and not isinstance(ev_data, dict):
            return JSONResponse({"error": "event.data must be an object"}, status_code=400)
    sid = x_session_id or "default"
    guardian = _get_session(sid)["guardian"]
    if req.event is not None:
        event = {"type": ev_type, "data": dict(ev_data or {})}
    else:
        event = {"type": "tool_call", "data": {"content": req.content}}
    event["data"]["_source"] = req.source
    matches = await guardian.evaluate(event, enforce=True, block_threshold=settings.block_threshold)
    blocking = [m for m in matches if is_blocking(m, settings.block_threshold)]
    body = {
        "blocked": bool(blocking),
        "threshold": settings.block_threshold,
        "matches": [
            {"rule": m.rule_name, "owasp_id": m.owasp_id, "threat_level": m.threat_level.value,
             "reason": m.reason, "blocking": m in blocking}
            for m in matches
        ],
    }
    return JSONResponse(body, status_code=403 if blocking else 200)


@app.post("/api/targets/verify")
async def verify_target(body: dict):
    """Verify a target app has guardian-tap installed and is reachable."""
    import httpx

    ws_url = body.get("ws_url", "")
    if not ws_url:
        return JSONResponse({"error": "No URL provided"}, status_code=400)

    health_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(health_url)
    except httpx.ConnectError:
        return {"status": "error", "code": "app_unreachable",
                "message": "Cannot reach the app. Check that the URL is correct and the app is deployed."}
    except httpx.TimeoutException:
        return {"status": "error", "code": "app_timeout",
                "message": "The app took too long to respond. It may be starting up. Try again in a minute."}
    except Exception as e:
        return {"status": "error", "code": "connection_error", "message": f"Connection error: {e}"}

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

    if not data.get("guardian_tap"):
        return {"status": "error", "code": "not_guardian_tap",
                "message": "The /ws-observe endpoint exists but is not a guardian-tap endpoint. It may be conflicting with another route in your app."}

    if not data.get("websocket_support", True):
        return {"status": "error", "code": "no_websocket_support",
                "message": "guardian-tap is installed, but WebSocket support is missing. For Python apps, run: pip install websockets (or add 'websockets' to requirements.txt) and redeploy."}

    try:
        import websockets
        async with websockets.connect(ws_url, open_timeout=5) as ws:
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

    # Get session ID from query param
    sid = websocket.query_params.get("session", "default")
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
