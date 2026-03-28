"""Gradient ADK entrypoint for deploying the self-healing agent to DigitalOcean."""

from __future__ import annotations

from gradient_adk import entrypoint
from langchain_core.messages import HumanMessage

from backend.agent.agent import create_agent
from backend.events.bus import event_bus

_agent = None


def get_agent():
    global _agent
    if _agent is None:
        _agent = create_agent(event_bus)
    return _agent


@entrypoint
async def main(input: dict, context=None) -> dict:
    """Process a single prompt through the guardian-protected agent.

    Input format: {"prompt": "your question here"}
    Returns: {"response": "agent response", "events": [...]}
    """
    prompt = input.get("prompt", "")
    if not prompt:
        return {"response": "No prompt provided", "events": []}

    agent = get_agent()

    # Collect events for this request
    queue = event_bus.subscribe()

    try:
        result = await agent.ainvoke(
            {
                "messages": [HumanMessage(content=prompt)],
                "scenario_id": 0,
            }
        )

        final_message = result["messages"][-1]
        response_text = final_message.content if hasattr(final_message, "content") else str(final_message)

        # Drain collected events
        events = []
        while not queue.empty():
            event = queue.get_nowait()
            events.append(event.model_dump())

        return {
            "response": response_text,
            "events": events,
        }
    finally:
        event_bus.unsubscribe(queue)
