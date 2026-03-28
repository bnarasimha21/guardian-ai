from __future__ import annotations

import time
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


# -- Events sent from Guardian to frontend --


class AgentActivityEvent(BaseModel):
    """A real agent event captured from the target system (ArchitectAI)."""
    type: str = "agent_activity"
    timestamp: float = Field(default_factory=time.time)
    event_type: str          # original event type from ArchitectAI (agent_start, planner_output, etc.)
    elapsed: float = 0       # elapsed time from ArchitectAI
    agent: str = ""          # which agent (planner, generator, evaluator, etc.)
    task_id: str = ""        # subtask id if applicable
    summary: str = ""        # human-readable summary of what happened
    data: dict = Field(default_factory=dict)  # raw event data


class DecisionEvent(BaseModel):
    """Guardian's block/allow decision for an agent action."""
    type: str = "decision"
    timestamp: float = Field(default_factory=time.time)
    event_type: str          # which event triggered this
    agent: str = ""
    task_id: str = ""
    action: DecisionAction
    rule_name: Optional[str] = None
    reason: Optional[str] = None
    threat_level: ThreatLevel = ThreatLevel.NONE
    owasp_id: str = ""       # e.g., "LLM01"
    owasp_label: str = ""    # e.g., "Prompt Injection"
    details: dict = Field(default_factory=dict)


class GuardianSummaryEvent(BaseModel):
    """Rolling summary of guardian evaluation stats."""
    type: str = "guardian_summary"
    timestamp: float = Field(default_factory=time.time)
    total_checked: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    by_rule: dict = Field(default_factory=dict)  # {rule_name: count}
    by_severity: dict = Field(default_factory=dict)  # {threat_level: count}
    per_app: dict = Field(default_factory=dict)  # {app_name: {checked, blocked, allowed, by_rule, by_severity}}


class StatusEvent(BaseModel):
    """Status updates for the monitoring session."""
    type: str = "status"
    timestamp: float = Field(default_factory=time.time)
    status: str  # "connected", "query_sent", "monitoring", "completed", "error"
    message: str = ""
