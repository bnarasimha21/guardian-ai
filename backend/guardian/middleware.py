from __future__ import annotations

import logging

from backend.events.bus import EventBus
from backend.events.models import DecisionAction, DecisionEvent, ThreatLevel

from .models import ThreatMatch
from .rules import ALL_RULES, ThreatRule

logger = logging.getLogger(__name__)

# OWASP LLM Top 10 labels for UI display
OWASP_LABELS = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Excessive Agency",
}


class Guardian:
    """Evaluates raw agent events against all threat rules.

    Reports ALL matching rules per event (not just the first).
    Only emits ALLOWED decisions periodically (not for every clean event).
    """

    def __init__(self, event_bus: EventBus, rules: list[ThreatRule] | None = None) -> None:
        self.event_bus = event_bus
        self.rules = rules or ALL_RULES
        self._allowed_count = 0

    async def evaluate(self, event: dict) -> list[ThreatMatch]:
        """Run ALL rules against an event. Returns list of all matches."""
        event_type = event.get("type", "unknown")
        data = event.get("data", {})

        all_matches: list[ThreatMatch] = []
        for rule in self.rules:
            matches = rule.check(event)
            all_matches.extend(matches)

        if all_matches:
            # Emit a decision for each match
            for match in all_matches:
                owasp_label = OWASP_LABELS.get(match.owasp_id, "")
                await self.event_bus.emit(
                    DecisionEvent(
                        event_type=event_type,
                        agent=data.get("agent", ""),
                        task_id=data.get("task_id", ""),
                        action=DecisionAction.BLOCKED,
                        rule_name=match.rule_name,
                        reason=match.reason,
                        threat_level=match.threat_level,
                        owasp_id=match.owasp_id,
                        owasp_label=owasp_label,
                        details=_safe_details(data),
                    )
                )
                logger.warning(
                    "BLOCKED [%s/%s] event=%s reason=%s",
                    match.rule_name,
                    match.owasp_id,
                    event_type,
                    match.reason,
                )
            self._allowed_count = 0
        else:
            self._allowed_count += 1
            # Only emit ALLOWED every 5th clean event to reduce noise
            if self._allowed_count <= 3 or self._allowed_count % 5 == 0:
                await self.event_bus.emit(
                    DecisionEvent(
                        event_type=event_type,
                        agent=data.get("agent", ""),
                        task_id=data.get("task_id", ""),
                        action=DecisionAction.ALLOWED,
                        threat_level=ThreatLevel.NONE,
                        details=_safe_details(data),
                    )
                )

        return all_matches


def _safe_details(data: dict) -> dict:
    """Extract a safe subset of event data for decision details."""
    details = {}
    for key in ("agent", "task_id", "score", "passed", "services", "complexity",
                 "criteria_count", "iteration", "service_count", "coherence_score",
                 "_source"):
        if key in data:
            details[key] = data[key]

    for key in ("specification", "content", "query", "output", "reasoning", "message"):
        if key in data and isinstance(data[key], str):
            details[key] = data[key][:200] + ("..." if len(data[key]) > 200 else "")

    return details
