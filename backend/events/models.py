from __future__ import annotations

import time
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Severity order, lowest first. Used to compare a match against the block threshold.
SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


class DecisionAction(str, Enum):
    ALLOWED = "allowed"
    FLAGGED = "flagged"            # seen, not stopped (observer tap, monitor mode, allow with signals)
    BLOCKED = "blocked"            # refused by an enforcing check
    REQUIRE_APPROVAL = "require_approval"  # held until a human approves or it times out


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
    # True when the event type is one GuardianAI knows how to summarise. Only a
    # display hint: every event is evaluated regardless.
    known_type: bool = True


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
    owasp_id: str = ""       # alias of owasp_llm, kept for older clients
    owasp_label: str = ""    # label of owasp_llm, e.g. "Prompt Injection"
    owasp_llm: str = ""      # OWASP Top 10 for LLM Applications 2025, e.g. "LLM01"
    owasp_agentic: str = ""  # OWASP Top 10 for Agentic Applications 2026, e.g. "ASI01"
    owasp_agentic_label: str = ""
    details: dict = Field(default_factory=dict)
    # Policy decision fields
    decision_id: str = ""
    phase: str = "call"
    effect: str = ""         # allow | deny | require_approval (call); allow | warn | redact | deny (result)
    enforced: bool = False
    observed: bool = False   # came from the passive tap, so it could not be enforced
    mode: str = ""
    policy_rule_id: str = ""
    tool_name: str = ""
    reasons: list[str] = Field(default_factory=list)
    matched_detectors: list[str] = Field(default_factory=list)
    approval_id: str = ""


class ApprovalEvent(BaseModel):
    """A human approval changed state: pending, approved, denied or used."""
    type: str = "approval"
    timestamp: float = Field(default_factory=time.time)
    change: str              # pending | approved | denied | used
    approval_id: str
    status: str              # pending | approved | denied
    reason: str = ""
    note: str = ""
    tool_name: str = ""
    server: Optional[str] = None
    agent: str = ""
    policy_rule_id: str = ""
    decision_id: str = ""
    arguments_sha256: str = ""
    arguments: dict = Field(default_factory=dict)   # flattened, values truncated
    diff_from: str = ""
    diff: list = Field(default_factory=list)        # [{path, change, before?, after?}]
    preview_truncated: bool = False   # arguments shown in part: no one-click approve
    diff_truncated: bool = False
    created_at: float = 0
    expires_at: float = 0
    resolved_at: Optional[float] = None
    resolved_by: str = ""
    grant_valid_until: Optional[float] = None
    uses: int = 0


class GuardianSummaryEvent(BaseModel):
    """Rolling summary of guardian evaluation stats."""
    type: str = "guardian_summary"
    timestamp: float = Field(default_factory=time.time)
    total_checked: int = 0
    total_flagged: int = 0
    total_allowed: int = 0
    total_blocked: int = 0
    by_rule: dict = Field(default_factory=dict)  # {rule_name: count}
    by_severity: dict = Field(default_factory=dict)  # {threat_level: count}
    per_app: dict = Field(default_factory=dict)  # {app_name: {checked, blocked, allowed, by_rule, by_severity}}


class StatusEvent(BaseModel):
    """Status updates for the monitoring session."""
    type: str = "status"
    timestamp: float = Field(default_factory=time.time)
    status: str  # "connected", "query_sent", "monitoring", "completed", "error"
    message: str = ""
