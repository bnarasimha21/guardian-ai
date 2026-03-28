"""WebSocket tap client that passively observes target agent systems."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Awaitable

import websockets

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
) -> None:
    """Connect to a target app's observer WebSocket and stream events.

    Reconnects automatically on disconnect.

    Args:
        name: Human-readable name of the target app.
        ws_url: WebSocket URL of the observer endpoint.
        on_event: Async callback(app_name, event_dict) for each event.
        on_disconnect: Async callback(app_name) on disconnect.
    """
    while True:
        try:
            logger.info("[%s] Connecting to %s", name, ws_url)
            async with websockets.connect(
                ws_url,
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
