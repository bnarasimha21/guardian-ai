from __future__ import annotations

import asyncio
import logging
from typing import Union

from .models import AgentActivityEvent, DecisionEvent, GuardianSummaryEvent, StatusEvent

logger = logging.getLogger(__name__)

Event = Union[AgentActivityEvent, DecisionEvent, GuardianSummaryEvent, StatusEvent]


class EventBus:
    """Simple async pub/sub event bus for streaming events to WebSocket clients."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Event]] = []

    def subscribe(self) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def emit(self, event: Event) -> None:
        logger.debug("Event emitted: %s", event.type)
        for queue in self._subscribers:
            await queue.put(event)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Global singleton
event_bus = EventBus()
