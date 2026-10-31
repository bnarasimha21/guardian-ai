"""Policy as code for tool calls: a small, versioned YAML format.

Why YAML rules and not Rego (OPA) or Cedar: GuardianAI is a reference you can
read in a gallery. A YAML file evaluated by ~400 lines of Python needs no
external runtime, and every decision can be traced back to one rule id.
The engine sits behind ``engine.evaluate(policy, call, ...) -> Decision``; an
OPA or Cedar backend would implement the same function (send the ToolCall and
detector matches as input, map the result to a Decision) and the HTTP API, the
MCP gateway and the approval queue would not change.
"""

from .engine import Decision, evaluate
from .loader import PolicyError, PolicyStore
from .models import Policy

__all__ = ["Decision", "evaluate", "Policy", "PolicyError", "PolicyStore"]
