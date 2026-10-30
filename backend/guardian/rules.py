"""Guardian threat detection rules.

Generic rules that work with ANY agent system. Rules inspect event data
by shape (text content, URLs, patterns) not by specific event type names.
OWASP mappings (LLM Top 10 2025 and Agentic Top 10 2026) live in taxonomy.py.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Optional

from backend.events.models import ThreatLevel
from .models import ThreatMatch


class ThreatRule(ABC):
    """Base class for threat detection rules."""

    name: str
    description: str

    @abstractmethod
    def check(self, event: dict) -> list[ThreatMatch]:
        """Return all matches (not just the first). Empty list = clean."""
        ...


def _extract_all_text(data: dict, max_depth: int = 3) -> str:
    """Recursively extract all string values from a dict."""
    if max_depth <= 0:
        return ""
    parts = []
    for value in data.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            parts.append(_extract_all_text(value, max_depth - 1))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(_extract_all_text(item, max_depth - 1))
    return " ".join(parts)


class PromptInjectionRule(ThreatRule):
    """Detects prompt injection patterns in any text content.
    OWASP mapping: see taxonomy.py."""

    name = "prompt_injection"
    description = "Prompt injection attempt detected"

    PATTERNS = [
        (r"ignore\s+(all\s+)?previous\s+instructions", "instruction override"),
        (r"ignore\s+(all\s+)?above", "instruction override"),
        (r"disregard\s+(all\s+)?prior", "instruction override"),
        (r"you\s+are\s+now\s+", "role hijacking"),
        (r"new\s+instructions?:", "instruction injection"),
        (r"system\s*:\s*you", "system prompt injection"),
        (r"<\s*system\s*>", "XML tag injection"),
        (r"\]\s*\[\s*system", "bracket injection"),
        (r"ADMIN\s*MODE", "privilege escalation via prompt"),
        (r"jailbreak", "explicit jailbreak"),
        (r"do\s+anything\s+now", "DAN pattern"),
        (r"pretend\s+you\s+(are|have)\s+no\s+(restrictions|rules)", "guardrail bypass"),
        (r"act\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored)", "guardrail bypass"),
        (r"developer\s+mode", "developer mode exploit"),
    ]

    def check(self, event: dict) -> list[ThreatMatch]:
        text = _extract_all_text(event.get("data", {}))
        if not text:
            return []
        matches = []
        for pattern, desc in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(ThreatMatch(
                    rule_name=self.name,
                    reason=f"Prompt injection: {desc}",
                    threat_level=ThreatLevel.CRITICAL,
                    matched_pattern=pattern,
                ))
        return matches


class SensitiveDataLeakRule(ThreatRule):
    """Detects API keys, secrets, or credentials in any event content.
    OWASP mapping: see taxonomy.py."""

    name = "sensitive_data_leak"
    description = "Sensitive data exposed in agent output"

    PATTERNS = [
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key (sk-*)"),
        (r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[a-zA-Z0-9]{16,}", "API key assignment"),
        (r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}", "password in output"),
        (r"(?:secret|token)\s*[=:]\s*['\"]?[a-zA-Z0-9]{16,}", "secret/token assignment"),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "private key"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal token"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
        (r"dop_v1_[a-zA-Z0-9]{64}", "DigitalOcean token"),
        (r"xox[bpas]-[a-zA-Z0-9\-]{10,}", "Slack token"),
        (r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.", "JWT token"),
        (r"[a-f0-9]{32,64}", None),  # checked separately for context
    ]

    def check(self, event: dict) -> list[ThreatMatch]:
        text = _extract_all_text(event.get("data", {}))
        if not text:
            return []
        matches = []
        for pattern, desc in self.PATTERNS:
            if desc is None:
                continue  # skip generic hex for now, too many false positives
            if re.search(pattern, text):
                matches.append(ThreatMatch(
                    rule_name=self.name,
                    reason=f"Sensitive data leak: {desc}",
                    threat_level=ThreatLevel.HIGH,
                    matched_pattern=pattern,
                ))
        return matches


class DataExfiltrationRule(ThreatRule):
    """Detects attempts to send data to suspicious external endpoints.
    OWASP mapping: see taxonomy.py."""

    name = "data_exfiltration"
    description = "Data exfiltration attempt via external endpoint"

    PATTERNS = [
        (r"webhook\.site", "webhook.site exfil endpoint"),
        (r"requestbin", "requestbin exfil endpoint"),
        (r"ngrok\.io", "ngrok tunnel"),
        (r"burpcollaborator", "Burp Collaborator"),
        (r"interact\.sh", "interactsh callback"),
        (r"pipedream", "pipedream webhook"),
        (r"hookbin", "hookbin exfil endpoint"),
        (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "raw IP address URL"),
        (r"curl\s+.*https?://", "curl to external URL"),
        (r"wget\s+", "wget download"),
        (r"fetch\(\s*['\"]https?://", "fetch() to external URL"),
    ]

    def check(self, event: dict) -> list[ThreatMatch]:
        text = _extract_all_text(event.get("data", {}))
        if not text:
            return []
        matches = []
        for pattern, desc in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(ThreatMatch(
                    rule_name=self.name,
                    reason=f"Data exfiltration risk: {desc}",
                    threat_level=ThreatLevel.CRITICAL,
                    matched_pattern=pattern,
                ))
        return matches


class SSRFRule(ThreatRule):
    """Detects Server-Side Request Forgery patterns.
    OWASP mapping: see taxonomy.py."""

    name = "ssrf"
    description = "Server-Side Request Forgery attempt"

    PATTERNS = [
        (r"https?://localhost[:/]", "localhost access"),
        (r"https?://127\.0\.0\.1[:/]", "loopback access"),
        (r"https?://0\.0\.0\.0[:/]", "wildcard bind access"),
        (r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "private network (10.x)"),
        (r"https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", "private network (172.16-31.x)"),
        (r"https?://192\.168\.\d{1,3}\.\d{1,3}", "private network (192.168.x)"),
        (r"https?://169\.254\.\d{1,3}\.\d{1,3}", "cloud metadata endpoint (169.254.x)"),
        (r"https?://metadata\.google", "GCP metadata"),
    ]

    def check(self, event: dict) -> list[ThreatMatch]:
        text = _extract_all_text(event.get("data", {}))
        if not text:
            return []
        matches = []
        for pattern, desc in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(ThreatMatch(
                    rule_name=self.name,
                    reason=f"SSRF attempt: {desc}",
                    threat_level=ThreatLevel.HIGH,
                    matched_pattern=pattern,
                ))
        return matches


class DangerousCodeRule(ThreatRule):
    """Detects dangerous commands, code execution, and system access.
    OWASP mapping: see taxonomy.py."""

    name = "dangerous_code"
    description = "Dangerous command or code execution pattern"

    PATTERNS = [
        (r"\brm\s+(-rf|-fr|--recursive)", "destructive file deletion"),
        (r"/dev/tcp/", "reverse shell via /dev/tcp"),
        (r"\bmkfifo\b", "named pipe (reverse shell)"),
        (r"\bchmod\s+777", "world-writable permissions"),
        (r"\bsudo\b", "privilege escalation"),
        (r"\|\s*bash\b|\|\s*sh\b|\|\s*zsh\b", "piping to shell"),
        (r"os\.system\(", "Python os.system()"),
        (r"subprocess\.(run|call|Popen)\(", "Python subprocess"),
        (r"\beval\(", "eval() execution"),
        (r"\bexec\(", "exec() execution"),
        (r"__import__\(", "dynamic import"),
        (r"/etc/passwd|/etc/shadow", "system file access"),
        (r"\.env\b", "environment file access"),
        (r"\.\./\.\./", "path traversal"),
        (r"base64\s+(-d|--decode)", "base64 decode (obfuscation)"),
    ]

    def check(self, event: dict) -> list[ThreatMatch]:
        text = _extract_all_text(event.get("data", {}))
        if not text:
            return []
        matches = []
        for pattern, desc in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(ThreatMatch(
                    rule_name=self.name,
                    reason=f"Dangerous operation: {desc}",
                    threat_level=ThreatLevel.HIGH,
                    matched_pattern=pattern,
                ))
        return matches


class InjectionRule(ThreatRule):
    """Detects SQL injection, XSS, and command injection patterns in outputs.
    OWASP mapping: see taxonomy.py."""

    name = "injection"
    description = "Injection pattern detected in agent output"

    PATTERNS = [
        # SQL injection
        (r"(?:UNION\s+SELECT|DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b", "SQL injection"),
        (r"(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "SQL injection (tautology)"),
        (r";\s*(?:DROP|DELETE|ALTER|TRUNCATE)\s", "SQL injection (chained)"),
        # XSS
        (r"<script[^>]*>", "XSS (script tag)"),
        (r"javascript\s*:", "XSS (javascript: URI)"),
        (r"on(?:load|error|click|mouseover)\s*=", "XSS (event handler)"),
        # Command injection
        (r";\s*(?:cat|ls|whoami|id|uname)\b", "command injection"),
        (r"\$\(.*\)", "command substitution"),
        (r"`[^`]*`", None),  # skip backtick detection, too many false positives in code
    ]

    def check(self, event: dict) -> list[ThreatMatch]:
        text = _extract_all_text(event.get("data", {}))
        if not text:
            return []
        matches = []
        for pattern, desc in self.PATTERNS:
            if desc is None:
                continue
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(ThreatMatch(
                    rule_name=self.name,
                    reason=f"Injection pattern: {desc}",
                    threat_level=ThreatLevel.HIGH,
                    matched_pattern=pattern,
                ))
        return matches


class UnauthorizedScopeRule(ThreatRule):
    """Detects when an agent drifts outside expected scope.
    OWASP mapping: see taxonomy.py."""

    name = "excessive_agency"
    description = "Agent action exceeds expected scope"

    PATTERNS = [
        (r"(?:execute|deploy|provision|create)\s+(?:the\s+)?(?:server|droplet|instance|cluster)", "real deployment attempt"),
        (r"(?:ssh|scp)\s+\w+@", "remote server access"),
        (r"doctl\s+", "DigitalOcean CLI execution"),
        (r"terraform\s+(?:apply|destroy)", "infrastructure mutation"),
        (r"kubectl\s+(?:apply|delete|exec)", "Kubernetes mutation"),
        (r"docker\s+(?:run|exec|push)", "container execution"),
        (r"aws\s+(?:s3|ec2|iam|lambda)\s+", "AWS CLI execution"),
        (r"gcloud\s+", "GCP CLI execution"),
    ]

    def check(self, event: dict) -> list[ThreatMatch]:
        text = _extract_all_text(event.get("data", {}))
        if not text:
            return []
        matches = []
        for pattern, desc in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(ThreatMatch(
                    rule_name=self.name,
                    reason=f"Scope violation: {desc}",
                    threat_level=ThreatLevel.MEDIUM,
                    matched_pattern=pattern,
                ))
        return matches


class EvaluationManipulationRule(ThreatRule):
    """Detects anomalous evaluation scores.
    OWASP mapping: see taxonomy.py."""

    name = "eval_manipulation"
    description = "Anomalous evaluation score detected"

    def check(self, event: dict) -> list[ThreatMatch]:
        data = event.get("data", {})
        score = data.get("score")

        if not isinstance(score, (int, float)):
            return []

        if score <= 2:
            return [ThreatMatch(
                rule_name=self.name,
                reason=f"Critically low score ({score}/10), possible adversarial input",
                threat_level=ThreatLevel.MEDIUM,
                matched_pattern=f"score={score}",
            )]

        return []


# All rules in evaluation order (highest severity first)
ALL_RULES: list[ThreatRule] = [
    PromptInjectionRule(),
    SensitiveDataLeakRule(),
    DataExfiltrationRule(),
    SSRFRule(),
    DangerousCodeRule(),
    InjectionRule(),
    UnauthorizedScopeRule(),
    EvaluationManipulationRule(),
]
