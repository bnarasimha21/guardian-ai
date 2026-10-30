"""Find tool calls inside events seen on the observer tap.

The tap forwards whatever the target app sends: its own event types, raw
OpenAI or Anthropic message objects, JSON responses with no ``type`` at all.
Instead of trusting an allowlist of event types, every event is searched for
tool-call shapes:

* ``{"tool": "name" | {"name": ...}, "arguments" | "args" | "input" | "parameters": {...}}``
* ``{"type": "tool_call" | "function_call", "name": ..., "arguments": ...}``
* OpenAI: ``{"tool_calls": [{"id", "function": {"name", "arguments": "<json>"}}]}``
  and the older ``{"function_call": {"name", "arguments": "<json>"}}``
* Anthropic: ``{"type": "tool_use", "id", "name", "input": {...}}``

Each one found becomes a ToolCall. Whatever is left of the event once the
tool calls are taken out is evaluated too, as ``guardian.event.<type>``, so
text outside a tool call (an LLM answer, a fetched page) is still checked.
"""

from __future__ import annotations

import json
from typing import Any

from backend.guardian.schema import LEGACY_EVENT_PREFIX, ToolCall

MAX_NODES = 5_000
ARG_KEYS = ("arguments", "args", "input", "parameters", "params")
SHAPED_TYPES = {"tool_call", "function_call", "tool_use", "tool"}


def _parse_args(value: Any) -> dict | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, RecursionError):
            return {"raw_arguments": value}
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    if value is None:
        return {}
    return {"value": value}


def _name_of(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value[:200]
    if isinstance(value, dict):
        name = value.get("name")
        if isinstance(name, str) and name:
            return name[:200]
    return None


def _as_call(node: dict, agent: str) -> ToolCall | None:
    # OpenAI tool call: {"id", "type": "function", "function": {"name", "arguments"}}
    fn = node.get("function")
    if isinstance(fn, dict) and isinstance(fn.get("name"), str) and "arguments" in fn:
        return ToolCall(name=fn["name"][:200], arguments=_parse_args(fn.get("arguments")) or {},
                        call_id=_str(node.get("id")), agent_name=agent)
    # Anthropic tool_use block
    if node.get("type") == "tool_use" and isinstance(node.get("name"), str):
        return ToolCall(name=node["name"][:200], arguments=_parse_args(node.get("input")) or {},
                        call_id=_str(node.get("id")), agent_name=agent)
    arg_key = next((k for k in ARG_KEYS if k in node), None)
    if arg_key is None:
        return None
    # {"tool": ..., "arguments": ...}
    name = _name_of(node.get("tool")) or _name_of(node.get("tool_name"))
    # {"type": "tool_call", "name": ..., "arguments": ...}
    if name is None and node.get("type") in SHAPED_TYPES:
        name = _name_of(node.get("name"))
    if name is None:
        return None
    server = node.get("server") if isinstance(node.get("server"), str) else None
    return ToolCall(name=name, server=server, arguments=_parse_args(node.get(arg_key)) or {},
                    call_id=_str(node.get("id") or node.get("call_id")), agent_name=agent)


def _str(v: Any) -> str | None:
    return str(v)[:200] if v is not None else None


def extract_tool_calls(event: dict, *, app_name: str = "") -> tuple[list[ToolCall], Any]:
    """Return (tool calls, remainder of the event with those calls removed)."""
    data = event.get("data") if isinstance(event.get("data"), dict) else None
    root: Any = data if data is not None else {k: v for k, v in event.items() if k not in ("type", "elapsed")}
    agent = root.get("agent") if isinstance(root, dict) else None
    agent = agent if isinstance(agent, str) and agent else app_name

    calls: list[ToolCall] = []
    taken: set[int] = set()
    stack: list[Any] = [root]
    seen = 0
    while stack and seen < MAX_NODES:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            call = _as_call(node, agent)
            if call is not None:
                call.event_type = str(event.get("type", "tool_call"))[:100]
                calls.append(call)
                taken.add(id(node))
                continue
            for k, v in node.items():
                if k == "function_call" and isinstance(v, dict) and isinstance(v.get("name"), str):
                    calls.append(ToolCall(name=v["name"][:200], arguments=_parse_args(v.get("arguments")) or {},
                                          agent_name=agent, event_type=str(event.get("type", "tool_call"))[:100]))
                    taken.add(id(v))
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(reversed(node))
    if id(root) in taken:
        remainder: Any = {}
    else:
        remainder = _without(root, taken) if taken else root
    return calls, remainder


def _without(value: Any, taken: set[int]) -> Any:
    """Copy of value with the taken dict nodes dropped (iterative)."""
    out: list[Any] = [None]
    stack: list[tuple[Any, Any, Any]] = [(value, out, 0)]
    while stack:
        src, parent, key = stack.pop()
        if isinstance(src, dict):
            new: dict = {}
            if isinstance(parent, list) and key is None:
                parent.append(new)
            else:
                parent[key] = new
            for k, v in src.items():
                if isinstance(v, dict) and id(v) in taken:
                    continue
                stack.append((v, new, k))
        elif isinstance(src, list):
            new_list: list = []
            if isinstance(parent, list) and key is None:
                parent.append(new_list)
            else:
                parent[key] = new_list
            # Push reversed so items are appended in order.
            for v in reversed(src):
                if isinstance(v, dict) and id(v) in taken:
                    continue
                stack.append((v, new_list, None))
        else:
            if isinstance(parent, list) and key is None:
                parent.append(src)
            else:
                parent[key] = src
    return out[0]


def synthetic_event_call(event: dict, remainder: Any, *, app_name: str = "") -> ToolCall:
    ev_type = event.get("type")
    ev_type = ev_type if isinstance(ev_type, str) and ev_type else "untyped"
    args = remainder if isinstance(remainder, dict) else {"value": remainder}
    agent = ""
    if isinstance(args, dict):
        a = args.get("agent") or args.get("name")
        agent = a if isinstance(a, str) else ""
    return ToolCall(name=LEGACY_EVENT_PREFIX + "".join(c if c.isalnum() or c in "_.-" else "_" for c in ev_type[:100]),
                    arguments=args, agent_name=agent or app_name, legacy=True, event_type=ev_type)


def has_content(value: Any) -> bool:
    """True if value holds any string or number (worth scanning)."""
    stack = [value]
    n = 0
    while stack and n < MAX_NODES:
        v = stack.pop()
        n += 1
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            if v != "":
                return True
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return False
