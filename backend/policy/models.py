"""Policy file schema (version 1). Unknown keys are errors, not silently ignored."""

from __future__ import annotations

import re
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.events.models import SEVERITY_ORDER
from backend.guardian.rules import RULE_NAMES

CALL_EFFECTS = ("allow", "deny", "require_approval")
RESULT_EFFECTS = ("allow", "warn", "redact", "deny")
SEVERITIES = ("low", "medium", "high", "critical", "block_threshold")

StrOrList = Union[str, list[str]]


def as_list(value: Optional[StrOrList]) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


PREDICATE_OPS = (
    "host_in", "host_not_in", "host_in_private_ranges", "host_not_in_private_ranges",
    "path_prefix", "max_length", "regex", "equals", "one_of", "exists",
)


class Predicate(_Strict):
    """A test on the argument value(s) at ``path``.

    ``path`` is dotted, with numeric list indexes and ``*`` for any key or
    item: ``url``, ``request.headers.*``, ``files.*.path``. Exactly one
    operator is set. ``quantifier`` says whether any or all values at the path
    must pass; the default depends on the rule effect (see engine.py).
    """

    path: str
    quantifier: Optional[Literal["any", "all"]] = None
    negate: bool = False
    host_in: Optional[list[str]] = None
    host_not_in: Optional[list[str]] = None
    host_in_private_ranges: Optional[bool] = None
    host_not_in_private_ranges: Optional[bool] = None
    path_prefix: Optional[StrOrList] = None
    max_length: Optional[int] = Field(default=None, ge=0)
    regex: Optional[str] = None
    equals: Any = None
    one_of: Optional[list[Any]] = None
    exists: Optional[bool] = None

    @model_validator(mode="after")
    def _one_operator(self) -> "Predicate":
        ops = [op for op in PREDICATE_OPS if op in self.model_fields_set]
        if len(ops) != 1:
            raise ValueError(
                f"argument predicate on '{self.path}' needs exactly one of {', '.join(PREDICATE_OPS)} (got {ops or 'none'})"
            )
        if self.regex is not None:
            try:
                re.compile(self.regex)
            except re.error as exc:
                raise ValueError(f"invalid regex {self.regex!r}: {exc}") from exc
        for flag in ("host_in_private_ranges", "host_not_in_private_ranges"):
            if flag in self.model_fields_set and getattr(self, flag) is not True:
                raise ValueError(f"{flag} only accepts true")
        return self

    @property
    def operator(self) -> str:
        return next(op for op in PREDICATE_OPS if op in self.model_fields_set)


class DetectorMatch(_Strict):
    """Holds when a detector fired: optionally one of ``rules``, at or above ``min_severity``."""

    rules: Optional[list[str]] = None
    min_severity: str = "low"

    @field_validator("rules")
    @classmethod
    def _known(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        for name in v or []:
            if name not in RULE_NAMES:
                raise ValueError(f"unknown detector '{name}' (known: {', '.join(RULE_NAMES)})")
        return v

    @field_validator("min_severity")
    @classmethod
    def _severity(cls, v: str) -> str:
        v = str(v).strip().lower()
        if v not in SEVERITIES:
            raise ValueError(f"min_severity must be one of {', '.join(SEVERITIES)}")
        return v


class Match(_Strict):
    """All present conditions must hold. An empty match holds for every call."""

    tool: Optional[StrOrList] = None
    server: Optional[StrOrList] = None
    agent: Optional[StrOrList] = None
    arguments: list[Predicate] = Field(default_factory=list)
    detectors: Optional[DetectorMatch] = None
    not_: Optional["Match"] = Field(default=None, alias="not")
    any: Optional[list["Match"]] = None


class ApprovalSettings(_Strict):
    timeout_seconds: float = Field(default=120, gt=0, le=86_400)
    # Once a call is approved, identical calls (same tool and arguments) are
    # allowed without a new approval for this many seconds. 0 = single use.
    grant_ttl_seconds: float = Field(default=0, ge=0, le=86_400)


class Rule(_Strict):
    id: str
    description: str = ""
    phase: Literal["call", "result"] = "call"
    match: Match = Field(default_factory=Match)
    effect: str
    reason: str = ""
    approval: Optional[ApprovalSettings] = None
    owasp_llm: str = ""
    owasp_agentic: str = ""

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9_.\-]{1,80}$", v):
            raise ValueError("rule id must be 1-80 characters of letters, digits, _ . -")
        return v

    @model_validator(mode="after")
    def _effect_for_phase(self) -> "Rule":
        allowed = CALL_EFFECTS if self.phase == "call" else RESULT_EFFECTS
        if self.effect not in allowed:
            raise ValueError(f"rule '{self.id}': effect for phase {self.phase} must be one of {', '.join(allowed)}")
        if self.approval is not None and self.effect != "require_approval":
            raise ValueError(f"rule '{self.id}': 'approval' only applies to require_approval rules")
        return self


class UntrustedInput(_Strict):
    """Argument paths that carry content the agent did not write (fetched pages, emails)."""

    tool: StrOrList = "*"
    paths: list[str]


class Policy(_Strict):
    version: Literal[1]
    mode: Literal["enforce", "monitor"] = "enforce"
    default_effect: Literal["allow", "deny", "require_approval"] = "deny"
    default_result_effect: Literal["allow", "warn", "redact", "deny"] = "allow"
    approval: ApprovalSettings = Field(default_factory=ApprovalSettings)
    untrusted_inputs: list[UntrustedInput] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> "Policy":
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id '{rule.id}'")
            seen.add(rule.id)
        return self


Match.model_rebuild()

SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITY_ORDER)}
