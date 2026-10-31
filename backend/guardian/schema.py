"""Request schema for the check API: a structured tool call.

``POST /api/check`` takes a tool call::

    {"tool": {"name": "http.fetch", "server": "web"},
     "arguments": {"url": "https://api.github.com"},
     "agent": {"id": "a-1", "name": "researcher"},
     "session_id": "optional",
     "call_id": "optional, echoed into telemetry",
     "trace_context": {"traceparent": "00-...", "tool_span": false}}

The older shapes keep working and are wrapped as synthetic tool calls:

* ``{"content": "..."}`` becomes tool ``guardian.content`` with
  ``arguments = {"content": "..."}``;
* ``{"event": {"type": T, "data": {...}}}`` becomes tool ``guardian.event.T``
  with ``arguments = data``.

``source`` (legacy) is used as the agent name when no agent is given.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

LEGACY_CONTENT_TOOL = "guardian.content"
LEGACY_EVENT_PREFIX = "guardian.event."
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.:/\-]{1,200}$")


class ToolRef(BaseModel):
    name: str
    server: Optional[str] = Field(default=None, max_length=200)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _TOOL_NAME.match(v):
            raise ValueError("tool.name must be 1-200 characters of letters, digits, and _ . : / -")
        return v


class AgentRef(BaseModel):
    id: str = Field(default="", max_length=200)
    name: str = Field(default="", max_length=200)


class TraceContext(BaseModel):
    traceparent: Optional[str] = Field(default=None, max_length=256)
    tracestate: Optional[str] = Field(default=None, max_length=1024)
    # True when the caller already has its own execute_tool span for this call:
    # GuardianAI then records a child "guardian.check" span instead of a second
    # execute_tool span.
    tool_span: bool = False


class CheckRequest(BaseModel):
    tool: Optional[ToolRef] = None
    arguments: Any = None
    agent: Optional[AgentRef] = None
    session_id: Optional[str] = Field(default=None, max_length=200)
    call_id: Optional[str] = Field(default=None, max_length=200)
    trace_context: Optional[TraceContext] = None
    # Legacy shapes
    content: Optional[str] = None
    event: Optional[dict] = None
    source: str = Field(default="api-check", max_length=200)

    @field_validator("agent", mode="before")
    @classmethod
    def _agent(cls, v: Any) -> Any:
        if isinstance(v, str):
            return {"name": v}
        return v

    @field_validator("tool", mode="before")
    @classmethod
    def _tool(cls, v: Any) -> Any:
        if isinstance(v, str):
            return {"name": v}
        return v


# The name used in the design notes for this request model.
ToolCallCheck = CheckRequest


class RequestError(ValueError):
    """The request is malformed; message is safe to return to the caller."""


@dataclass
class ToolCall:
    """What the policy engine evaluates."""

    name: str
    arguments: dict = field(default_factory=dict)
    server: str | None = None
    agent_id: str = ""
    agent_name: str = ""
    call_id: str | None = None
    legacy: bool = False
    event_type: str = "tool_call"

    def canonical(self) -> dict:
        return {"tool": self.name, "server": self.server, "arguments": self.arguments}


def to_tool_call(req: CheckRequest) -> ToolCall:
    """Normalise any accepted request shape to a ToolCall. Raises RequestError."""
    shapes = sum(x is not None for x in (req.tool, req.content, req.event))
    if shapes == 0:
        raise RequestError("Provide 'tool' (with 'arguments'), or legacy 'content' or 'event'")
    if shapes > 1:
        raise RequestError("Provide only one of 'tool', 'content' or 'event'")
    agent = req.agent or AgentRef()
    # The legacy "source" label doubles as the agent name when none is given.
    agent_name = agent.name or (req.source if req.source != "api-check" or req.tool is None else "")
    if req.tool is not None:
        args = req.arguments
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise RequestError("'arguments' must be an object")
        return ToolCall(
            name=req.tool.name, server=req.tool.server, arguments=args,
            agent_id=agent.id, agent_name=agent_name, call_id=req.call_id,
        )
    if req.arguments is not None:
        raise RequestError("'arguments' needs 'tool'")
    if req.content is not None:
        return ToolCall(
            name=LEGACY_CONTENT_TOOL, arguments={"content": req.content},
            agent_id=agent.id, agent_name=agent_name, call_id=req.call_id, legacy=True,
            event_type="tool_call",
        )
    ev = req.event or {}
    ev_type = ev.get("type", "tool_call")
    ev_data = ev.get("data")
    if not isinstance(ev_type, str) or not _TOOL_NAME.match(ev_type):
        raise RequestError("event.type must be a short string")
    if ev_data is not None and not isinstance(ev_data, dict):
        raise RequestError("event.data must be an object")
    return ToolCall(
        name=LEGACY_EVENT_PREFIX + ev_type, arguments=dict(ev_data or {}),
        agent_id=agent.id, agent_name=agent_name, call_id=req.call_id, legacy=True,
        event_type=ev_type,
    )
