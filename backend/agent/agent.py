from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Annotated

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

from backend.config import settings
from backend.events.bus import EventBus
from backend.events.models import ToolResultEvent
from backend.guardian.middleware import Guardian

from .prompts import AGENT_SYSTEM_PROMPT
from .tools import ALL_TOOLS

logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    scenario_id: int


def create_agent(event_bus: EventBus):
    """Create a LangGraph agent with guardian-protected tools."""

    llm = ChatOpenAI(
        model=settings.model_name,
        base_url=settings.inference_base_url,
        api_key=settings.gradient_model_access_key,
        temperature=0,
        max_tokens=1024,
    )

    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    guardian = Guardian(event_bus=event_bus)

    # Tool lookup by name
    tool_map = {t.name: t for t in ALL_TOOLS}

    async def agent_node(state: AgentState) -> dict:
        """Call the LLM with the current messages."""
        messages = [{"role": "system", "content": AGENT_SYSTEM_PROMPT}] + state["messages"]
        response = await llm_with_tools.ainvoke(messages)
        return {"messages": [response]}

    async def guardian_tool_node(state: AgentState) -> dict:
        """Intercept tool calls through the guardian before executing."""
        last_message = state["messages"][-1]
        scenario_id = state.get("scenario_id", 0)

        results = []
        for tool_call in last_message.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            # Guardian evaluation
            threat = await guardian.evaluate(tool_name, tool_args, scenario_id=scenario_id)

            if threat is not None:
                # BLOCKED
                blocked_msg = f"BLOCKED by guardian [{threat.rule_name}]: {threat.reason}"
                results.append(
                    ToolMessage(
                        content=blocked_msg,
                        tool_call_id=tool_call["id"],
                        name=tool_name,
                    )
                )
                await event_bus.emit(
                    ToolResultEvent(
                        scenario_id=scenario_id,
                        tool_name=tool_name,
                        result=blocked_msg,
                        was_blocked=True,
                    )
                )
            else:
                # ALLOWED - execute the tool
                tool_fn = tool_map[tool_name]
                try:
                    result = await asyncio.to_thread(tool_fn.invoke, tool_args)
                    result_str = str(result)
                except Exception as e:
                    result_str = f"Error: {e}"

                results.append(
                    ToolMessage(
                        content=result_str,
                        tool_call_id=tool_call["id"],
                        name=tool_name,
                    )
                )
                await event_bus.emit(
                    ToolResultEvent(
                        scenario_id=scenario_id,
                        tool_name=tool_name,
                        result=result_str[:200],
                        was_blocked=False,
                    )
                )

        return {"messages": results}

    def should_continue(state: AgentState) -> str:
        """Route: if the last message has tool calls, go to guardian. Otherwise, end."""
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "guardian_tools"
        return END

    # Build the graph
    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("guardian_tools", guardian_tool_node)

    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", should_continue, {"guardian_tools": "guardian_tools", END: END})
    graph.add_edge("guardian_tools", "agent")

    return graph.compile()
