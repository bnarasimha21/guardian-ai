from __future__ import annotations

import logging

from backend.events.bus import EventBus
from backend.events.models import SEVERITY_ORDER, DecisionAction, DecisionEvent, GuardianSummaryEvent, ThreatLevel

from .models import ThreatMatch
from .rules import ALL_RULES, ThreatRule

logger = logging.getLogger(__name__)

OWASP_LABELS = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Excessive Agency",
}


class Guardian:
    """Evaluates raw agent events against all threat rules.

    Reports ALL matching rules per event. Emits a rolling summary
    instead of individual ALLOWED cards.

    Events seen through the passive tap are only FLAGGED: the tap cannot stop
    the target app. Content submitted through evaluate(..., enforce=True) (the
    /api/check endpoint) is BLOCKED when a match reaches the block threshold.
    """

    def __init__(self, event_bus: EventBus, rules: list[ThreatRule] | None = None) -> None:
        self.event_bus = event_bus
        self.rules = rules or ALL_RULES
        self._total_checked = 0
        self._total_flagged = 0
        self._total_allowed = 0
        self._by_rule: dict[str, int] = {}
        self._by_severity: dict[str, int] = {}
        # Per-app stats
        self._per_app: dict[str, dict] = {}  # {app_name: {checked, blocked, allowed, by_rule, by_severity}}

    async def evaluate(self, event: dict, enforce: bool = False, block_threshold: str = "high") -> list[ThreatMatch]:
        """Run ALL rules against an event. Returns list of all matches.

        With enforce=True, matches at or above block_threshold are emitted as
        BLOCKED decisions (the caller is expected to refuse the content).
        """
        event_type = event.get("type", "unknown")
        data = event.get("data", {})

        all_matches: list[ThreatMatch] = []
        for rule in self.rules:
            matches = rule.check(event)
            all_matches.extend(matches)

        self._total_checked += 1
        source = data.get("_source", "")
        if source and source not in self._per_app:
            self._per_app[source] = {"checked": 0, "flagged": 0, "allowed": 0, "by_rule": {}, "by_severity": {}}
        app_stats = self._per_app.get(source)
        if app_stats:
            app_stats["checked"] += 1

        if all_matches:
            self._total_flagged += 1
            if app_stats:
                app_stats["flagged"] += 1
            for match in all_matches:
                self._by_rule[match.rule_name] = self._by_rule.get(match.rule_name, 0) + 1
                self._by_severity[match.threat_level.value] = self._by_severity.get(match.threat_level.value, 0) + 1
                if app_stats:
                    app_stats["by_rule"][match.rule_name] = app_stats["by_rule"].get(match.rule_name, 0) + 1
                    app_stats["by_severity"][match.threat_level.value] = app_stats["by_severity"].get(match.threat_level.value, 0) + 1

                owasp_label = OWASP_LABELS.get(match.owasp_id, "")
                await self.event_bus.emit(
                    DecisionEvent(
                        event_type=event_type,
                        agent=data.get("agent", ""),
                        task_id=data.get("task_id", ""),
                        action=DecisionAction.BLOCKED if enforce and is_blocking(match, block_threshold) else DecisionAction.FLAGGED,
                        rule_name=match.rule_name,
                        reason=match.reason,
                        threat_level=match.threat_level,
                        owasp_id=match.owasp_id,
                        owasp_label=owasp_label,
                        details=_safe_details(data),
                    )
                )
                logger.warning(
                    "FLAGGED [%s/%s] event=%s reason=%s",
                    match.rule_name,
                    match.owasp_id,
                    event_type,
                    match.reason,
                )
        else:
            self._total_allowed += 1
            if app_stats:
                app_stats["allowed"] += 1

        # Emit rolling summary with per-app breakdown
        await self.event_bus.emit(
            GuardianSummaryEvent(
                total_checked=self._total_checked,
                total_flagged=self._total_flagged,
                total_allowed=self._total_allowed,
                by_rule=dict(self._by_rule),
                by_severity=dict(self._by_severity),
                per_app=dict(self._per_app),
            )
        )

        return all_matches


def is_blocking(match: ThreatMatch, threshold: str) -> bool:
    """True if the match severity is at or above the threshold."""
    if threshold not in SEVERITY_ORDER:
        threshold = "high"
    return SEVERITY_ORDER.index(match.threat_level.value) >= SEVERITY_ORDER.index(threshold)


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
