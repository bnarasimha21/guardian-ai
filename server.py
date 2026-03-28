from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config import settings
from backend.events.bus import event_bus
from backend.events.models import AgentActivityEvent, StatusEvent
from backend.guardian.middleware import Guardian
from backend.targets import target_store
from backend.tap.client import observe_agent, ACTIONABLE_EVENTS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="GuardianAI - Real-Time Agent Defense Monitor")
guardian = Guardian(event_bus=event_bus)

# Active observer tasks per target name
_observer_tasks: dict[str, asyncio.Task] = {}

# Skip events that are noise (progress ticks, individual LLM tokens, keepalives)
SKIP_EVENTS = {
    "decomposition_start", "synthesis_start", "wave_start", "subtask_start",
    "token",         # individual LLM streaming tokens
    "ping", "pong",  # WebSocket keepalives
    "heartbeat",
}


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


async def on_agent_event(app_name: str, event: dict):
    event_type = event.get("type", "unknown")
    data = event.get("data", {})
    elapsed = event.get("elapsed", 0)

    if event_type in SKIP_EVENTS:
        return

    await event_bus.emit(
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
        # Inject source into event data so Guardian decisions carry it
        enriched = {**event, "data": {**data, "_source": app_name}}
        await guardian.evaluate(enriched)


async def on_connect(app_name: str):
    target_store.set_status(app_name, "connected")
    await event_bus.emit(
        StatusEvent(status="target_connected", message=f"{app_name} connected")
    )


async def on_disconnect(app_name: str):
    target_store.set_status(app_name, "disconnected")
    await event_bus.emit(
        StatusEvent(status="target_disconnected", message=f"{app_name} disconnected")
    )


def _start_observer(name: str, ws_url: str) -> None:
    """Start an observer task for a target app."""
    if name in _observer_tasks and not _observer_tasks[name].done():
        return

    async def _observe_wrapper():
        target_store.set_status(name, "connecting")
        await observe_agent(name, ws_url, on_agent_event, on_connect, on_disconnect)

    _observer_tasks[name] = asyncio.create_task(_observe_wrapper())
    logger.info("Observer started for %s", name)


def _stop_observer(name: str) -> None:
    """Stop an observer task."""
    if name in _observer_tasks:
        _observer_tasks[name].cancel()
        del _observer_tasks[name]
        target_store.set_status(name, "disconnected")
        logger.info("Observer stopped for %s", name)


@app.on_event("startup")
async def startup():
    """Start observers for all previously registered targets."""
    for target in target_store.list_all():
        _start_observer(target.name, target.ws_url)


# ---- API ----

class AddTargetRequest(BaseModel):
    name: str
    ws_url: str


@app.post("/api/targets")
async def add_target(req: AddTargetRequest):
    if target_store.get(req.name):
        return JSONResponse({"error": f"Target '{req.name}' already exists"}, status_code=409)
    target = target_store.add(req.name, req.ws_url)
    _start_observer(target.name, target.ws_url)
    return {"status": "added", "target": {"name": target.name, "ws_url": target.ws_url}}


@app.delete("/api/targets/{name}")
async def remove_target(name: str):
    _stop_observer(name)
    if target_store.remove(name):
        return {"status": "removed", "name": name}
    return JSONResponse({"error": "Target not found"}, status_code=404)


@app.get("/api/targets")
async def list_targets():
    targets = [
        {"name": t.name, "ws_url": t.ws_url, "status": t.status}
        for t in target_store.list_all()
    ]
    return {"targets": targets}


@app.post("/api/targets/verify")
async def verify_target(body: dict):
    """Verify a target app has guardian-tap installed and is reachable.
    Checks the HTTP health endpoint before attempting WebSocket connection."""
    import httpx

    ws_url = body.get("ws_url", "")
    if not ws_url:
        return JSONResponse({"error": "No URL provided"}, status_code=400)

    # Convert ws(s):// to http(s):// for the health check
    health_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

    # Step 1: Check if the app is reachable at all
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(health_url)
    except httpx.ConnectError:
        return {
            "status": "error",
            "code": "app_unreachable",
            "message": "Cannot reach the app. Check that the URL is correct and the app is deployed.",
        }
    except httpx.TimeoutException:
        return {
            "status": "error",
            "code": "app_timeout",
            "message": "The app took too long to respond. It may be starting up. Try again in a minute.",
        }
    except Exception as e:
        return {
            "status": "error",
            "code": "connection_error",
            "message": f"Connection error: {e}",
        }

    # Step 2: Check if guardian-tap is installed
    if resp.status_code == 404:
        return {
            "status": "error",
            "code": "guardian_tap_not_installed",
            "message": "The app is running, but guardian-tap is not installed. Make sure you have added 'from guardian_tap import attach_observer; attach_observer(app)' to your server file and redeployed.",
        }

    if resp.status_code != 200:
        return {
            "status": "error",
            "code": "unexpected_status",
            "message": f"Got HTTP {resp.status_code} from the app. Expected 200. The app may have a route conflict at /ws-observe.",
        }

    # Step 3: Validate the health response
    try:
        data = resp.json()
    except Exception:
        return {
            "status": "error",
            "code": "invalid_response",
            "message": "The /ws-observe endpoint exists but did not return valid JSON. It may be conflicting with another route in your app.",
        }

    if not data.get("guardian_tap"):
        return {
            "status": "error",
            "code": "not_guardian_tap",
            "message": "The /ws-observe endpoint exists but is not a guardian-tap endpoint. It may be conflicting with another route in your app.",
        }

    if not data.get("websocket_support", True):
        return {
            "status": "error",
            "code": "no_websocket_support",
            "message": "guardian-tap is installed, but WebSocket support is missing. For Python apps, run: pip install websockets (or add 'websockets' to requirements.txt) and redeploy.",
        }

    # Step 4: Try the actual WebSocket connection
    try:
        import websockets
        async with websockets.connect(ws_url, open_timeout=5) as ws:
            await ws.close()
    except Exception as e:
        return {
            "status": "error",
            "code": "websocket_failed",
            "message": f"Health check passed but WebSocket connection failed: {e}. This may be a proxy or firewall issue. Make sure your hosting platform supports WebSocket connections.",
        }

    return {
        "status": "ok",
        "code": "ready",
        "message": "All checks passed. Ready to connect.",
        "details": {
            "version": data.get("version"),
            "framework": data.get("framework"),
        },
    }


# ---- Frontend ----

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
async def index():
    return FileResponse("frontend/index.html")


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    queue = event_bus.subscribe()
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event.model_dump())
    except WebSocketDisconnect:
        event_bus.unsubscribe(queue)
    except Exception:
        event_bus.unsubscribe(queue)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
