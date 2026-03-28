from __future__ import annotations

import asyncio
import logging

from langchain_core.messages import HumanMessage

from backend.events.bus import EventBus
from backend.events.models import AgentResponseEvent, AttackEvent, StatusEvent

from .scenarios import SCENARIOS, AttackScenario

logger = logging.getLogger(__name__)


async def run_red_team(
    agent,
    event_bus: EventBus,
    delay_seconds: int = 6,
    scenarios: list[AttackScenario] | None = None,
) -> None:
    """Execute all red-team attack scenarios sequentially against the agent."""

    scenarios = scenarios or SCENARIOS
    total = len(scenarios)

    await event_bus.emit(
        StatusEvent(status="started", total_scenarios=total, current_scenario=0)
    )

    for i, scenario in enumerate(scenarios, 1):
        logger.info("Running scenario %d/%d: %s", i, total, scenario.category)

        # Emit attack event
        await event_bus.emit(
            AttackEvent(
                scenario_id=scenario.id,
                category=scenario.category,
                prompt=scenario.prompt,
                description=scenario.description,
            )
        )

        await event_bus.emit(
            StatusEvent(status="running", total_scenarios=total, current_scenario=i)
        )

        # Run the agent with this adversarial prompt
        try:
            result = await agent.ainvoke(
                {
                    "messages": [HumanMessage(content=scenario.prompt)],
                    "scenario_id": scenario.id,
                }
            )

            # Extract final response
            final_message = result["messages"][-1]
            response_text = final_message.content if hasattr(final_message, "content") else str(final_message)

            await event_bus.emit(
                AgentResponseEvent(
                    scenario_id=scenario.id,
                    response=response_text[:500],
                )
            )
        except Exception as e:
            logger.error("Scenario %d failed: %s", scenario.id, e)
            await event_bus.emit(
                AgentResponseEvent(
                    scenario_id=scenario.id,
                    response=f"Agent error: {e}",
                )
            )

        # Delay between scenarios for visual effect
        if i < total:
            await asyncio.sleep(delay_seconds)

    await event_bus.emit(
        StatusEvent(status="completed", total_scenarios=total, current_scenario=total)
    )
    logger.info("Red team run completed: %d scenarios executed", total)
