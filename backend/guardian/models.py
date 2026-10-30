from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from backend.events.models import ThreatLevel

from .taxonomy import owasp_for_rule


@dataclass
class ThreatMatch:
    """One detector rule that fired on a payload.

    ``owasp_llm`` and ``owasp_agentic`` default to the rule's mapping in
    ``taxonomy.py``. ``owasp_id`` is kept as an alias of ``owasp_llm`` so older
    API consumers that read ``owasp_id`` keep working.
    """

    rule_name: str
    reason: str
    threat_level: ThreatLevel
    matched_pattern: Optional[str] = None
    owasp_id: str = ""
    owasp_llm: str = ""
    owasp_agentic: str = ""
    # Every distinct reason this rule produced for the payload (deduplicated).
    reasons: list[str] = field(default_factory=list)
    # JSON paths of the argument values that triggered the rule.
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        default_llm, default_agentic = owasp_for_rule(self.rule_name)
        if not self.owasp_llm:
            self.owasp_llm = default_llm
        if not self.owasp_agentic:
            self.owasp_agentic = default_agentic
        self.owasp_id = self.owasp_llm
        if not self.reasons:
            self.reasons = [self.reason]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "owasp_id": self.owasp_id,
            "owasp_llm": self.owasp_llm,
            "owasp_agentic": self.owasp_agentic,
            "threat_level": self.threat_level.value,
            "reason": self.reason,
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
        }
