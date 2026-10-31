"""Evaluate a tool call against a policy.

Order of work for one call:

1. Run every detector over the arguments. Paths listed under
   ``untrusted_inputs`` for this tool are marked untrusted, which turns on the
   detectors' weak patterns there (fetched pages, emails, search results).
2. Walk the rules for the phase (``call`` before the tool runs, ``result``
   after) in file order. The first rule whose ``match`` holds decides.
3. No rule matched: ``default_effect`` (call) or ``default_result_effect``.

Matching rules:

* ``tool``, ``server``, ``agent``: fnmatch globs, case-insensitive. ``agent``
  is matched against the API-key principal when the caller authenticated with
  a key, otherwise against the self-reported ``agent.id`` and ``agent.name``.
* ``arguments``: every predicate must hold. A predicate's default quantifier
  is ``all`` for ``allow`` rules (every value at the path must pass, so one
  bad URL in a list is not let through) and ``any`` for other effects (one
  bad value is enough to deny). A path with no values fails the predicate,
  so an allow rule never matches a call that lacks the argument it checks.
* ``detectors``: at least one detector fired, optionally restricted to
  ``rules`` and to ``min_severity`` (``block_threshold`` means the server's
  BLOCK_THRESHOLD).
* ``not``: the nested match does not hold. ``any``: one of the nested
  matches holds.

Host predicates parse the value as a URL (or a bare host) and never resolve
DNS: ``host_not_in_private_ranges`` is a literal check. Whatever performs the
fetch must still resolve, check and pin the address (backend/netguard.py does
this for GuardianAI's own outbound requests).
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

from backend.events.models import SEVERITY_ORDER
from backend.guardian import rules as detectors
from backend.guardian.models import ThreatMatch
from backend.guardian.schema import ToolCall
from backend.guardian.taxonomy import owasp_for_rule
from backend.netguard import classify_host_literal

from .loader import LoadedPolicy
from .models import ApprovalSettings, Match, Predicate, Rule, as_list

BLOCKING_CALL_EFFECTS = ("deny", "require_approval")


@dataclass
class Decision:
    decision_id: str
    phase: str
    effect: str
    enforced: bool
    mode: str
    rule_id: str
    reasons: list[str]
    matches: list[ThreatMatch]
    deciding_detectors: list[str]
    tool: str
    policy_version: int
    policy_sha256: str
    approval: ApprovalSettings | None = None
    owasp_llm: str = ""
    owasp_agentic: str = ""
    rule_description: str = ""
    redacted: Any = None
    # The API-key name the caller authenticated as, if any. Unlike the agent
    # id in the request body, the caller cannot choose it.
    principal: str = ""

    @property
    def matched_detectors(self) -> list[str]:
        return [m.rule_name for m in self.matches]

    @property
    def blocked(self) -> bool:
        """The caller must not proceed (enforce mode only)."""
        if not self.enforced:
            return False
        if self.phase == "call":
            return self.effect in BLOCKING_CALL_EFFECTS
        return self.effect == "deny"

    @property
    def top_match(self) -> ThreatMatch | None:
        pool = [m for m in self.matches if m.rule_name in self.deciding_detectors] or self.matches
        if not pool:
            return None
        return max(pool, key=lambda m: SEVERITY_ORDER.index(m.threat_level.value))

    def to_dict(self) -> dict:
        out = {
            "decision_id": self.decision_id,
            "phase": self.phase,
            "effect": self.effect,
            "blocked": self.blocked,
            "enforced": self.enforced,
            "mode": self.mode,
            "rule_id": self.rule_id,
            "reasons": list(self.reasons),
            "matched_detectors": self.matched_detectors,
            "tool": self.tool,
            "owasp_llm": self.owasp_llm,
            "owasp_agentic": self.owasp_agentic,
            "policy": {"version": self.policy_version, "sha256": self.policy_sha256},
        }
        if self.approval is not None and self.effect == "require_approval":
            out["approval"] = self.approval.model_dump()
        return out


@dataclass
class _Ctx:
    call: ToolCall
    principal: str | None
    matches: list[ThreatMatch]
    block_threshold: str
    payload: Any  # what argument predicates read: arguments (call) or result (result phase)


def untrusted_paths_for(policy, tool_name: str) -> list[str]:
    paths: list[str] = []
    for entry in policy.untrusted_inputs:
        if _glob_any(tool_name, as_list(entry.tool)):
            paths.extend(entry.paths)
    return paths


SCAN_LIMIT_RULE_ID = "builtin-deny-unscanned"


def evaluate(
    loaded: LoadedPolicy,
    call: ToolCall,
    *,
    phase: str = "call",
    principal: str | None = None,
    block_threshold: str = "high",
    result: Any = None,
    matches: list[ThreatMatch] | None = None,
) -> Decision:
    """Decide on one tool call (phase "call") or its output (phase "result")."""
    policy = loaded.policy
    if matches is None:
        if phase == "call":
            matches = detectors.detect(call.arguments, untrusted_paths=untrusted_paths_for(policy, call.name))
        else:
            # Tool output is content the agent did not write: all of it is untrusted.
            matches = detectors.detect(result, all_untrusted=True)
    ctx = _Ctx(call=call, principal=principal, matches=matches, block_threshold=block_threshold,
               payload=call.arguments if phase == "call" else result)

    chosen: Rule | None = None
    deciding: list[str] = []
    for rule in policy.rules:
        if rule.phase != phase:
            continue
        holds, used = _match(rule.match, ctx, rule.effect)
        if holds:
            chosen, deciding = rule, used
            break

    if chosen is not None:
        effect = chosen.effect
        rule_id = chosen.id
        reasons = [chosen.reason or chosen.description or f"Matched policy rule '{chosen.id}'"]
    else:
        effect = policy.default_effect if phase == "call" else policy.default_result_effect
        rule_id = "default"
        reasons = [
            f"No policy rule matched tool '{call.name}'; the default {'' if phase == 'call' else 'result '}effect is {effect}"
        ]
    # Input too large to scan fully is never known to be clean, so it is
    # refused whatever the rules and BLOCK_THRESHOLD say. Otherwise padding a
    # payload past the limit would turn every detector off.
    limit_hit = next((m for m in matches if m.rule_name == detectors.SCAN_LIMIT_RULE), None)
    if limit_hit is not None and effect != "deny":
        effect = "deny"
        rule_id = SCAN_LIMIT_RULE_ID
        chosen = None
        deciding = [detectors.SCAN_LIMIT_RULE]
        reasons = ["The input is too large to scan fully, so it is refused (fail closed)"]
    for m in matches:
        if m.rule_name in deciding:
            for r in m.reasons:
                if r not in reasons:
                    reasons.append(r)

    owasp_llm = chosen.owasp_llm if chosen else ""
    owasp_agentic = chosen.owasp_agentic if chosen else ""
    if not owasp_llm and not owasp_agentic:
        top = _top([m for m in matches if m.rule_name in deciding])
        if top is not None:
            owasp_llm, owasp_agentic = top.owasp_llm, top.owasp_agentic
        elif effect in ("deny", "require_approval"):
            owasp_llm, owasp_agentic = owasp_for_rule("policy")

    approval = None
    if effect == "require_approval":
        approval = chosen.approval if chosen and chosen.approval else policy.approval

    redacted = None
    if phase == "result" and effect == "redact":
        names = deciding or [m.rule_name for m in matches]
        redacted = detectors.redact(result, names)
        # Redaction rewrites the text as written. A secret that was only seen
        # in a normalised or decoded spelling (split by zero-width characters,
        # fullwidth, base64) survives it, so check, and withhold the result
        # rather than pass on a "redacted" copy that still carries the secret.
        # The placeholder is longer than most secrets, so redacting can push the
        # copy over the scan limit; a copy that cannot be fully re-scanned is
        # not known to be clean either.
        left = [m for m in detectors.detect(redacted, all_untrusted=True)
                if m.rule_name in names or m.rule_name == detectors.SCAN_LIMIT_RULE]
        if left:
            effect = "deny"
            redacted = None
            reasons.append(
                "Redaction could not remove every match (the text is obfuscated, for example split by "
                "invisible characters or base64-encoded), so the result is withheld"
            )

    return Decision(
        decision_id=uuid.uuid4().hex,
        phase=phase,
        effect=effect,
        enforced=policy.mode == "enforce",
        mode=policy.mode,
        rule_id=rule_id,
        reasons=reasons,
        matches=matches,
        deciding_detectors=deciding,
        tool=call.name,
        policy_version=policy.version,
        policy_sha256=loaded.sha256,
        approval=approval,
        owasp_llm=owasp_llm,
        owasp_agentic=owasp_agentic,
        rule_description=chosen.description if chosen else "",
        redacted=redacted,
        principal=principal or "",
    )


def _top(matches: list[ThreatMatch]) -> ThreatMatch | None:
    if not matches:
        return None
    return max(matches, key=lambda m: SEVERITY_ORDER.index(m.threat_level.value))


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _glob_any(value: str, patterns: Iterable[str]) -> bool:
    v = (value or "").lower()
    return any(fnmatch.fnmatchcase(v, p.lower()) for p in patterns)


def _match(m: Match, ctx: _Ctx, effect: str) -> tuple[bool, list[str]]:
    used: list[str] = []
    if m.tool is not None and not _glob_any(ctx.call.name, as_list(m.tool)):
        return False, []
    if m.server is not None and not _glob_any(ctx.call.server or "", as_list(m.server)):
        return False, []
    if m.agent is not None:
        identities = [ctx.principal] if ctx.principal else [i for i in (ctx.call.agent_id, ctx.call.agent_name) if i]
        if not any(_glob_any(i, as_list(m.agent)) for i in identities):
            return False, []
    for pred in m.arguments:
        if not _predicate(pred, ctx.payload, effect):
            return False, []
    if m.detectors is not None:
        threshold = m.detectors.min_severity
        if threshold == "block_threshold":
            threshold = ctx.block_threshold
        floor = SEVERITY_ORDER.index(threshold) if threshold in SEVERITY_ORDER else SEVERITY_ORDER.index("high")
        hits = [
            x for x in ctx.matches
            if (m.detectors.rules is None or x.rule_name in m.detectors.rules)
            and SEVERITY_ORDER.index(x.threat_level.value) >= floor
        ]
        if not hits:
            return False, []
        used.extend(x.rule_name for x in hits)
    if m.not_ is not None:
        inner, _ = _match(m.not_, ctx, effect)
        if inner:
            return False, []
    if m.any is not None:
        for sub in m.any:
            ok, sub_used = _match(sub, ctx, effect)
            if ok:
                used.extend(u for u in sub_used if u not in used)
                break
        else:
            return False, []
    return True, used


def resolve_path(data: Any, path: str) -> list[Any]:
    """Values at a dotted path. ``*`` matches every key or list item."""
    if path in ("", "$"):
        return [data]
    current = [data]
    for seg in path.split("."):
        nxt: list[Any] = []
        for v in current:
            if seg == "*":
                if isinstance(v, dict):
                    nxt.extend(v.values())
                elif isinstance(v, list):
                    nxt.extend(v)
            elif isinstance(v, dict):
                if seg in v:
                    nxt.append(v[seg])
            elif isinstance(v, list) and seg.isdigit():
                i = int(seg)
                if i < len(v):
                    nxt.append(v[i])
        current = nxt
        if not current:
            break
    return current


_UNSAFE_URL_CHARS = re.compile(r"[\\\s\x00-\x1f\x7f]")


def host_of(value: Any) -> str | None:
    """Hostname of a URL or bare host, lowercased. None if it cannot be trusted.

    Values with backslashes, whitespace or control characters are refused:
    Python's parser and browsers or HTTP clients disagree on them
    (``https://evil.com\\@api.github.com`` is api.github.com to urlsplit and
    evil.com to WHATWG parsers).
    """
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    if _UNSAFE_URL_CHARS.search(value):
        return None
    text = value if "://" in value else "//" + value.lstrip("/")
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme and parts.scheme.lower() not in ("http", "https", "ws", "wss"):
        return None
    if not host:
        return None
    return host.rstrip(".").lower()


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _normalise_path(value: str) -> str | None:
    if "\x00" in value:
        return None
    value = value.replace("\\", "/")
    if value.startswith("file://"):
        value = value[len("file://"):]
    norm = posixpath.normpath(value)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


def _under(path: str, prefix: str) -> bool:
    prefix = _normalise_path(prefix) or ""
    if prefix == "/":
        return path.startswith("/")
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _test_one(pred: Predicate, value: Any) -> bool:
    op = pred.operator
    if op in ("host_in", "host_not_in"):
        host = host_of(value)
        inside = host is not None and _glob_any(host, getattr(pred, op) or [])
        return inside if op == "host_in" else not inside
    if op == "host_in_private_ranges":
        host = host_of(value)
        return host is not None and classify_host_literal(host) is not None
    if op == "host_not_in_private_ranges":
        host = host_of(value)
        return host is not None and classify_host_literal(host) is None
    if op == "path_prefix":
        if not isinstance(value, str):
            return False
        norm = _normalise_path(value)
        return norm is not None and any(_under(norm, p) for p in as_list(pred.path_prefix))
    if op == "max_length":
        return len(_as_text(value)) <= (pred.max_length or 0)
    if op == "regex":
        return re.search(pred.regex or "", _as_text(value)) is not None
    if op == "equals":
        return value == pred.equals
    if op == "one_of":
        return value in (pred.one_of or [])
    raise AssertionError(op)


def _predicate(pred: Predicate, payload: Any, effect: str) -> bool:
    values = resolve_path(payload, pred.path)
    if pred.operator == "exists":
        result = bool(values) == bool(pred.exists)
    elif not values:
        result = False
    else:
        quantifier = pred.quantifier or ("all" if effect == "allow" else "any")
        tests = (_test_one(pred, v) for v in values)
        result = all(tests) if quantifier == "all" else any(tests)
    return (not result) if pred.negate else result
