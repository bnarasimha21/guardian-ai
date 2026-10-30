from __future__ import annotations

import logging

from backend.events.bus import EventBus
from backend.events.models import (
    SEVERITY_ORDER, DecisionAction, DecisionEvent, GuardianSummaryEvent, ThreatLevel,
)

from .models import ThreatMatch
from .schema import ToolCall
from .taxonomy import agentic_label, llm_label

logger = logging.getLogger(__name__)

# Distinct `source` values tracked in per_app; further sources aggregate under "other"
# so the emitted summary cannot grow without bound.
MAX_TRACKED_SOURCES = 100
OTHER_SOURCE = "other"


def action_for(decision, *, observed: bool) -> DecisionAction:
    """How a policy decision is shown on the dashboard."""
    if observed or not decision.enforced:
        return DecisionAction.FLAGGED if (decision.effect != "allow" or decision.matches) else DecisionAction.ALLOWED
    if decision.phase == "call" and decision.effect == "require_approval":
        return DecisionAction.REQUIRE_APPROVAL
    if decision.blocked:
        return DecisionAction.BLOCKED
    if decision.effect != "allow" or decision.matches:
        return DecisionAction.FLAGGED
    return DecisionAction.ALLOWED


class Guardian:
    """Per-session bookkeeping for policy decisions.

    The policy engine (backend/policy) decides; Guardian records the decision,
    keeps the rolling stats and emits one DecisionEvent card per decision that
    is not a clean allow, plus a rolling summary.

    Decisions on events seen through the passive tap are ``observed``: the tap
    is a copy of the traffic and cannot stop anything, so they show as FLAGGED
    whatever the policy said. Decisions made for /api/check or the MCP gateway
    are enforced (unless the policy is in monitor mode).
    """

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._total_checked = 0
        self._total_flagged = 0
        self._total_allowed = 0
        self._total_blocked = 0
        self._total_pending = 0
        self._by_rule: dict[str, int] = {}
        self._by_severity: dict[str, int] = {}
        self._per_app: dict[str, dict] = {}

    def _app_stats(self, source: str) -> dict | None:
        if source and not isinstance(source, str):
            source = str(source)
        if source and source not in self._per_app and len(self._per_app) >= MAX_TRACKED_SOURCES:
            source = OTHER_SOURCE
        if source and source not in self._per_app:
            self._per_app[source] = {"checked": 0, "flagged": 0, "allowed": 0, "blocked": 0,
                                     "by_rule": {}, "by_severity": {}}
        return self._per_app.get(source)

    async def record(
        self,
        decision,
        call: ToolCall,
        *,
        source: str = "",
        observed: bool = False,
        details: dict | None = None,
        approval_id: str = "",
        force_card: bool = False,
    ) -> DecisionEvent | None:
        """Update stats and emit the decision card. Returns the card, if any.

        A clean allow normally gets no card; ``force_card`` emits one anyway
        (a call a human approved is worth showing).
        """
        self._total_checked += 1
        app = self._app_stats(source)
        if app is not None:
            app["checked"] += 1

        action = action_for(decision, observed=observed)
        if action == DecisionAction.BLOCKED:
            self._total_blocked += 1
            if app is not None:
                app["blocked"] = app.get("blocked", 0) + 1
        if action == DecisionAction.REQUIRE_APPROVAL:
            self._total_pending += 1

        for match in decision.matches:
            self._by_rule[match.rule_name] = self._by_rule.get(match.rule_name, 0) + 1
            self._by_severity[match.threat_level.value] = self._by_severity.get(match.threat_level.value, 0) + 1
            if app is not None:
                app["by_rule"][match.rule_name] = app["by_rule"].get(match.rule_name, 0) + 1
                app["by_severity"][match.threat_level.value] = app["by_severity"].get(match.threat_level.value, 0) + 1

        card: DecisionEvent | None = None
        if action == DecisionAction.ALLOWED:
            self._total_allowed += 1
            if app is not None:
                app["allowed"] += 1
        else:
            self._total_flagged += 1
            if app is not None:
                app["flagged"] += 1
        if action != DecisionAction.ALLOWED or force_card:
            card = self._card(decision, call, action, observed=observed, source=source,
                              details=details or {}, approval_id=approval_id)
            await self.event_bus.emit(card)
            logger.warning(
                "%s [%s] tool=%s effect=%s rule=%s reason=%s",
                action.value.upper(), card.rule_name, call.name, decision.effect, decision.rule_id,
                card.reason,
            )

        await self.emit_summary()
        return card

    async def emit_summary(self) -> None:
        await self.event_bus.emit(
            GuardianSummaryEvent(
                total_checked=self._total_checked,
                total_flagged=self._total_flagged,
                total_allowed=self._total_allowed,
                total_blocked=self._total_blocked,
                by_rule=dict(self._by_rule),
                by_severity=dict(self._by_severity),
                per_app=dict(self._per_app),
            )
        )

    def _card(self, decision, call: ToolCall, action: DecisionAction, *, observed: bool,
              source: str, details: dict, approval_id: str) -> DecisionEvent:
        top: ThreatMatch | None = decision.top_match
        policy_driven = decision.effect != "allow" and not decision.deciding_detectors
        if top is not None and not policy_driven:
            rule_name = top.rule_name
            level = top.threat_level
        else:
            rule_name = "policy"
            level = ThreatLevel.HIGH if decision.effect == "deny" else ThreatLevel.MEDIUM
            if top is not None and SEVERITY_ORDER.index(top.threat_level.value) > SEVERITY_ORDER.index(level.value):
                level = top.threat_level
        if decision.effect == "allow" and top is not None:
            reason = top.reason
        else:
            reason = "; ".join(decision.reasons[:3])
        safe = _safe_details(call.arguments)
        safe.update(details)
        if source:
            safe["_source"] = source
        return DecisionEvent(
            event_type=call.event_type if call.legacy else "tool_call",
            agent=call.agent_name or call.agent_id,
            task_id="",
            action=action,
            rule_name=rule_name,
            reason=reason,
            threat_level=level,
            owasp_id=decision.owasp_llm,
            owasp_label=llm_label(decision.owasp_llm),
            owasp_llm=decision.owasp_llm,
            owasp_agentic=decision.owasp_agentic,
            owasp_agentic_label=agentic_label(decision.owasp_agentic),
            details=safe,
            decision_id=decision.decision_id,
            phase=decision.phase,
            effect=decision.effect,
            enforced=decision.enforced and not observed,
            observed=observed,
            mode=decision.mode,
            policy_rule_id=decision.rule_id,
            tool_name=call.name,
            reasons=list(decision.reasons),
            matched_detectors=decision.matched_detectors,
            approval_id=approval_id,
        )


def is_blocking(match: ThreatMatch, threshold: str) -> bool:
    """True if the match severity is at or above the threshold."""
    threshold = str(threshold).strip().lower()
    if threshold not in SEVERITY_ORDER or threshold == "none":
        threshold = "high"
    return SEVERITY_ORDER.index(match.threat_level.value) >= SEVERITY_ORDER.index(threshold)


def _safe_details(data) -> dict:
    """A short, display-safe subset of the arguments for the decision card."""
    if not isinstance(data, dict):
        return {}
    details = {}
    for key in ("agent", "task_id", "score", "passed", "services", "complexity",
                "criteria_count", "iteration", "service_count", "coherence_score", "_source"):
        if key in data and isinstance(data[key], (str, int, float, bool)):
            details[key] = data[key]
    for key in ("specification", "content", "query", "output", "reasoning", "message",
                "url", "path", "command", "text", "page"):
        if key in data and isinstance(data[key], str):
            details[key] = data[key][:200] + ("..." if len(data[key]) > 200 else "")
    return details
