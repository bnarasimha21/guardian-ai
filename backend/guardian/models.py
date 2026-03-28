from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from backend.events.models import ThreatLevel


@dataclass
class ThreatMatch:
    rule_name: str
    reason: str
    threat_level: ThreatLevel
    matched_pattern: Optional[str] = None
    owasp_id: str = ""  # e.g., "LLM01", "LLM06"
