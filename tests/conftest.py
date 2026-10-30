"""Shared fixtures. Every test runs offline: DNS, outbound HTTP and Supabase are
replaced, and per-session target files go to a temp directory."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute

import backend.targets as targets_mod
import backend.usage_logger as usage_logger
import server


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Fresh per-test state: sessions dir, in-memory sessions, no Supabase."""
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    monkeypatch.setattr(targets_mod, "TARGETS_DIR", sessions_dir)
    monkeypatch.setattr(targets_mod.session_store, "_sessions", {})
    monkeypatch.setattr(usage_logger, "SUPABASE_URL", "")
    monkeypatch.setattr(usage_logger, "SUPABASE_KEY", "")
    for sess in list(server._sessions.values()):
        for task in sess["observers"].values():
            task.cancel()
    server._sessions.clear()
    yield
    for sess in list(server._sessions.values()):
        for task in sess["observers"].values():
            task.cancel()
    server._sessions.clear()


@pytest.fixture
def client():
    with TestClient(server.app) as c:
        yield c


class FakeDNS:
    """Resolver stand-in: hostname -> list of addresses. Unknown names fail."""

    def __init__(self) -> None:
        self.records: dict[str, list[str]] = {}
        self.lookups: list[str] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.lookups.append(host)
        if host not in self.records:
            raise OSError(f"NXDOMAIN {host}")
        return list(self.records[host])


@pytest.fixture(autouse=True)
def _restore_app_state():
    """app.state is a starlette State; monkeypatch.undo deletes its attributes
    instead of restoring them, so save and restore the hooks by hand."""
    saved = dict(server.app.state._state)
    yield
    server.app.state._state.clear()
    server.app.state._state.update(saved)


@pytest.fixture
def fake_dns():
    dns = FakeDNS()
    server.app.state.resolver = dns
    return dns


class RecordingTransport(httpx.MockTransport):
    """httpx mock transport that records every request it is asked to send."""

    def __init__(self, handler) -> None:
        self.requests: list[httpx.Request] = []

        def _record(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return handler(request)

        super().__init__(_record)


@pytest.fixture
def http_mock():
    """Install a recording transport for the verify health check.

    Usage: ``transport = http_mock(lambda request: httpx.Response(200, json={...}))``
    """

    def install(handler):
        transport = RecordingTransport(handler)
        server.app.state.verify_transport = transport
        return transport

    return install


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ThreadedServer:
    """Run an ASGI app under a real uvicorn server on 127.0.0.1 in a thread."""

    def __init__(self, app, port: int | None = None) -> None:
        self.port = port or free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning", lifespan="on")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("server did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=10)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


class FakeTapApp:
    """A minimal app that speaks the guardian-tap protocol on /ws-observe.

    GET returns the health JSON; a WebSocket client receives every event in
    ``events`` once connected, then the socket stays open until the server stops.
    """

    def __init__(self, events: list | None = None) -> None:
        self.events = list(events or [])
        self.ws_connections = 0

        async def health(request):
            return JSONResponse({"guardian_tap": True, "version": "test", "framework": "starlette",
                                 "websocket_support": True})

        async def observe(websocket):
            await websocket.accept()
            self.ws_connections += 1
            for event in self.events:
                await websocket.send_text(event if isinstance(event, str) else json.dumps(event))
            try:
                while True:
                    await websocket.receive_text()
            except Exception:
                return

        self.app = Starlette(routes=[Route("/ws-observe", health), WebSocketRoute("/ws-observe", observe)])


@pytest.fixture
def tap_server():
    """Factory: start a FakeTapApp under real uvicorn; returns (tap, ThreadedServer)."""
    started: list[ThreadedServer] = []

    def start(events=None):
        tap = FakeTapApp(events)
        srv = ThreadedServer(tap.app).__enter__()
        started.append(srv)
        return tap, srv

    yield start
    for srv in started:
        srv.__exit__(None, None, None)


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("condition not met in time")
