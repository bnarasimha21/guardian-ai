"""Pluggable model-based detectors.

The built-in detectors in ``rules.py`` are regular expressions and URL
checks. A ``ModelDetector`` lets a classifier (a local model, a hosted
moderation endpoint, anything that scores text) run beside them and feed the
same policy engine:

    from backend.guardian.detectors import ModelDetector

    class MyInjectionModel(ModelDetector):
        name = "injection_model"
        description = "Fine-tuned prompt-injection classifier"
        owasp_llm = "LLM01"
        owasp_agentic = "ASI01"
        threshold = 0.8
        level = ThreatLevel.HIGH

        def score(self, text: str) -> float:
            return my_model.predict_proba(text)

Register it in code with ``register_model_detector(MyInjectionModel())``, or
without code changes by setting

    GUARDIAN_MODEL_DETECTORS=my_package.detectors:MyInjectionModel

(comma-separated ``module:attribute`` entries; the attribute may be an
instance, a ModelDetector subclass, or a zero-argument factory). Nothing is
registered by default, so the default install has no model dependency.

A registered detector runs on every string field of every scanned payload
(including the normalised and base64-decoded variants), its name becomes
valid in a policy's ``detectors.rules`` list, and its matches carry the OWASP
ids it declares.
"""

from __future__ import annotations

import importlib
import logging
import os
from abc import ABC, abstractmethod

from backend.events.models import ThreatLevel

from ..models import ThreatMatch
from ..rules import ScanInput, ThreatRule, register_rule, unregister_rule

logger = logging.getLogger(__name__)

ENV_VAR = "GUARDIAN_MODEL_DETECTORS"


class ModelDetector(ABC):
    """A classifier that scores one string from 0.0 (benign) to 1.0 (attack).

    Attributes a subclass sets:

    * ``name``: detector name, used in policies and reports. Must not clash
      with a built-in detector.
    * ``description``: one line for humans.
    * ``owasp_llm`` / ``owasp_agentic``: OWASP ids its matches carry.
    * ``threshold``: a score at or above this is a match.
    * ``level``: the ThreatLevel a match gets (the policy's block_threshold
      decides whether that level blocks).
    * ``untrusted_only``: only score fields the policy marks as untrusted
      content (fetched pages, tool results), not the agent's own arguments.
    * ``fail_closed``: if ``score`` raises, report a match at ``level`` instead
      of logging and skipping. Off by default so an unavailable model does not
      block all traffic; turn it on when the detector is a required control.
    """

    name: str = ""
    description: str = ""
    owasp_llm: str = ""
    owasp_agentic: str = ""
    threshold: float = 0.5
    level: ThreatLevel = ThreatLevel.HIGH
    untrusted_only: bool = False
    fail_closed: bool = False
    min_chars: int = 1

    @abstractmethod
    def score(self, text: str) -> float:
        """Return the probability that ``text`` is an attack."""


class ModelRule(ThreatRule):
    """Adapts a ModelDetector to the ThreatRule interface used by ``detect``."""

    def __init__(self, detector: ModelDetector) -> None:
        if not detector.name or not isinstance(detector.name, str):
            raise ValueError(f"{type(detector).__name__} must set a non-empty 'name'")
        if not 0.0 <= float(detector.threshold) <= 1.0:
            raise ValueError(f"{detector.name}: threshold must be between 0 and 1")
        if not isinstance(detector.level, ThreatLevel):
            raise ValueError(f"{detector.name}: level must be a ThreatLevel")
        self.detector = detector
        self.name = detector.name
        self.description = detector.description or detector.name

    def _match(self, reason: str, score: float | None, evidence: list[str]) -> ThreatMatch:
        d = self.detector
        return ThreatMatch(
            rule_name=d.name, reason=reason, threat_level=d.level,
            matched_pattern=None if score is None else f"score={score:.3f}>={d.threshold}",
            owasp_llm=d.owasp_llm, owasp_agentic=d.owasp_agentic, evidence=evidence,
        )

    def scan(self, scan: ScanInput) -> list[ThreatMatch]:
        d = self.detector
        best: float | None = None
        evidence: list[str] = []
        scored: set[tuple[str, str]] = set()
        for f in scan.fields:
            if d.untrusted_only and not f.untrusted:
                continue
            if len(f.value) < d.min_chars or (f.path, f.value) in scored:
                continue
            scored.add((f.path, f.value))
            try:
                s = float(d.score(f.value))
            except Exception as exc:  # a broken model must not crash the request
                if d.fail_closed:
                    return [self._match(f"{d.name} could not score the input ({type(exc).__name__}); "
                                        "failing closed", None, [f.path or "$"])]
                logger.warning("model detector %s failed on %s: %s", d.name, f.path, exc)
                continue
            if s != s:  # NaN counts as a failure to score
                continue
            if s >= d.threshold:
                if f.path not in evidence:
                    evidence.append(f.path or "$")
                best = s if best is None else max(best, s)
        if best is None:
            return []
        return [self._match(f"{d.description or d.name}: score {best:.2f} (threshold {d.threshold})",
                            best, evidence)]


def register_model_detector(detector: ModelDetector) -> ModelRule:
    """Run ``detector`` on every scan from now on. Returns the adapter."""
    rule = ModelRule(detector)
    register_rule(rule)
    return rule


def unregister_model_detector(name: str) -> None:
    unregister_rule(name)


def _resolve(spec: str) -> ModelDetector:
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise ValueError(f"{ENV_VAR} entry {spec!r} must look like 'package.module:Attribute'")
    try:
        obj = getattr(importlib.import_module(module_name), attr)
    except (ImportError, AttributeError) as exc:
        raise ValueError(f"{ENV_VAR} entry {spec!r} cannot be loaded: {exc}") from exc
    if isinstance(obj, ModelDetector):
        return obj
    if isinstance(obj, type) and issubclass(obj, ModelDetector):
        return obj()
    if callable(obj):
        made = obj()
        if isinstance(made, ModelDetector):
            return made
    raise ValueError(f"{ENV_VAR} entry {spec!r} is not a ModelDetector, subclass or factory")


def load_from_env(value: str | None = None) -> list[ModelRule]:
    """Register every detector named in ``GUARDIAN_MODEL_DETECTORS``.

    Raises ValueError on a bad entry, so a misconfigured detector stops the
    server at startup instead of silently not running.
    """
    raw = os.environ.get(ENV_VAR, "") if value is None else value
    out = []
    for spec in (s.strip() for s in raw.split(",")):
        if spec:
            out.append(register_model_detector(_resolve(spec)))
            logger.info("model detector %s registered from %s", out[-1].name, spec)
    return out


__all__ = [
    "ENV_VAR", "ModelDetector", "ModelRule", "load_from_env",
    "register_model_detector", "unregister_model_detector",
]
