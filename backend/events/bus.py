from __future__ import annotations

import asyncio
import logging
from typing import Union

from .models import AgentActivityEvent, ApprovalEvent, DecisionEvent, GuardianSummaryEvent, StatusEvent

logger = logging.getLogger(__name__)

Event = Union[AgentActivityEvent, ApprovalEvent, DecisionEvent, GuardianSummaryEvent, StatusEvent]

# Per-subscriber queue size. A browser that stops reading loses its oldest
# events instead of growing server memory without bound.
DEFAULT_MAXSIZE = 1000


class EventBus:
    """Async pub/sub bus for streaming events to WebSocket clients.

    Queues are bounded; when a subscriber is full the oldest queued event is
    dropped to make room (counted in ``dropped``).
    """

    def __init__(self, maxsize: int = DEFAULT_MAXSIZE) -> None:
        self._subscribers: list[asyncio.Queue[Event]] = []
        self.maxsize = maxsize
        self.dropped = 0

    def subscribe(self) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self.maxsize)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def emit(self, event: Event) -> None:
        logger.debug("Event emitted: %s", event.type)
        for queue in list(self._subscribers):
            while True:
                try:
                    queue.put_nowait(event)
                    break
                except asyncio.QueueFull:
                    try:
                        queue.get_nowait()
                        self.dropped += 1
                    except asyncio.QueueEmpty:
                        pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Global singleton
event_bus = EventBus()
