"""WebSocket tap client that passively observes target agent systems."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Awaitable

import websockets

from backend.netguard import Resolver, TargetRejected, check_target_url

logger = logging.getLogger(__name__)

# Events that carry meaningful data worth evaluating
ACTIONABLE_EVENTS = {
    "agent_start",
    "planner_output",
    "generator_output",
    "evaluation",
    "docs_fetched",
    "decomposition_result",
    "synthesis_complete",
    "validation_result",
    "subtask_start",
    "subtask_complete",
    "wave_start",
    "tool_call",
    "tool_result",
    # SSE-style events (from TravelPlanner, etc.)
    "plan",
    "agent_start",
    "agent_result",
    "agent_error",
    "synthesis",
    "complete",
}


async def observe_agent(
    name: str,
    ws_url: str,
    on_event: Callable[[str, dict], Awaitable[None]],
    on_connect: Callable[[str], Awaitable[None]] | None = None,
    on_disconnect: Callable[[str], Awaitable[None]] | None = None,
    *,
    allow_private: bool = False,
    resolver: Resolver | None = None,
    on_reject: Callable[[str, str], Awaitable[None]] | None = None,
) -> None:
    """Connect to a target app's observer WebSocket and stream events.

    Reconnects automatically on disconnect.

    Args:
        name: Human-readable name of the target app.
        ws_url: WebSocket URL of the observer endpoint.
        on_event: Async callback(app_name, event_dict) for each event.
        on_disconnect: Async callback(app_name) on disconnect.
        allow_private: Permit loopback and private addresses (local development).
        resolver: DNS resolver override (tests).
        on_reject: Async callback(app_name, message) when the URL is refused by
            the address check; the observer stops instead of retrying.

    The URL is re-checked before every connection attempt and the connection is
    pinned to the address that was checked, so a DNS change cannot turn a
    registered public target into a request to an internal address.
    """
    while True:
        try:
            target = await check_target_url(ws_url, allow_private=allow_private, resolver=resolver)
        except TargetRejected as exc:
            if exc.code == "dns_failed":
                # Transient: retry like any other connection failure.
                logger.warning("[%s] %s Retrying in 5s...", name, exc.message)
                if on_disconnect:
                    await on_disconnect(name)
                await asyncio.sleep(5)
                continue
            logger.error("[%s] Refusing to observe %s: %s", name, ws_url, exc.message)
            if on_reject:
                await on_reject(name, exc.message)
            return
        try:
            logger.info("[%s] Connecting to %s (%s)", name, ws_url, target.pinned_ip)
            async with websockets.connect(
                ws_url,
                host=target.pinned_ip,
                port=target.port,
                proxy=None,
                open_timeout=15,
                close_timeout=5,
                max_size=2**22,
                ping_interval=30,
                ping_timeout=10,
            ) as ws:
                logger.info("[%s] Connected", name)
                if on_connect:
                    await on_connect(name)

                async for message in ws:
                    try:
                        event = json.loads(message)
                    except json.JSONDecodeError:
                        continue

                    # Skip non-dict events (e.g., arrays, primitives)
                    if not isinstance(event, dict):
                        continue

                    # Skip guardian-tap's own health check responses
                    if event.get("guardian_tap"):
                        continue

                    await on_event(name, event)

        except websockets.exceptions.ConnectionClosed as e:
            logger.warning("[%s] Connection closed: %s. Reconnecting in 5s...", name, e)
        except Exception as e:
            logger.error("[%s] Connection failed: %s. Reconnecting in 5s...", name, e)

        if on_disconnect:
            await on_disconnect(name)

        await asyncio.sleep(5)
