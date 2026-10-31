"""Guardian threat detectors.

Detectors are generic: they inspect values by shape (text, URLs, numbers), not
by event type. Every detector sees each string value together with its JSON
path, so a match says which argument triggered it, and a detector can treat
some paths as untrusted (content the agent fetched, as opposed to content the
agent wrote).

Each string is also scanned in normalised form when that differs from the
original: Unicode NFKC, zero-width and bidi control characters removed,
common Cyrillic and Greek look-alike letters folded to Latin, percent-escapes
decoded ("%20"), and runs of base64 decoded (one level) when they decode to
readable text. So "ign\u200bore previous instructions", fullwidth or homoglyph
spellings, "ignore%20previous%20instructions" and a base64-wrapped command are
seen as what they say. Matches from a variant
carry the original field's path.

Walking is iterative with no depth cap. A node limit and a character limit
(on the text as sent; the variants get a separate, larger allowance) bound
the work; a payload over either limit produces a ``scan_limit_exceeded``
match instead of being silently half-scanned (fail closed).

OWASP mappings (LLM Top 10 2025 and Agentic Top 10 2026) live in taxonomy.py.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator
from urllib.parse import unquote, urlsplit

from backend.events.models import SEVERITY_ORDER, ThreatLevel
from backend.netguard import classify_host_literal, parse_ip_literal

from .models import ThreatMatch

MAX_NODES = 10_000
MAX_TOTAL_CHARS = 1_000_000
# Normalised and decoded variants may add up to this multiple of the limit.
VARIANT_ALLOWANCE = 3
JOINED_PATH = "$joined"


# ---------------------------------------------------------------------------
# Walking payloads
# ---------------------------------------------------------------------------


@dataclass
class ScanField:
    """One string value and where it came from."""

    path: str          # dotted path with list indexes, e.g. "results.0.page"
    key: str           # last dict key on the path, lowercased ("" for list items)
    value: str
    untrusted: bool = False


@dataclass
class ScanInput:
    fields: list[ScanField] = field(default_factory=list)
    numbers: dict[str, float] = field(default_factory=dict)
    limit_exceeded: str | None = None


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

# Invisible characters used to split keywords: zero-width, joiners, word
# joiner, invisible operators, BOM, soft hyphen, bidi embeddings and isolates.
# Variation selectors (U+FE00 to U+FE0F and U+E0100 to U+E01EF) and the tag
# characters that are not printable ASCII (U+E0000 to U+E001F, U+E007F) go too.
_INVISIBLE = re.compile("[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
                        "\ufe00-\ufe0f\U000e0000-\U000e001f\U000e007f\U000e0100-\U000e01ef]")
# Unicode tag characters U+E0020 to U+E007E shadow printable ASCII and render
# as nothing, so a sentence can be hidden in them ("ASCII smuggling"). A run
# of them is spelled out as the ASCII it shadows, set off by spaces.
_TAG_RUN = re.compile("[\U000e0020-\U000e007e]+")


def _untag(m: re.Match) -> str:
    return " " + "".join(chr(ord(ch) - 0xE0000) for ch in m.group(0)) + " "
# Look-alike letters that NFKC leaves alone (Cyrillic and Greek), folded to Latin.
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
    "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0458": "j", "\u0501": "d", "\u04bb": "h",
    "\u04cf": "l", "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
    "\u0406": "I", "\u0405": "S", "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i",
    "\u03ba": "k", "\u03bd": "v", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
    "\u039f": "O", "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I",
    "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
})
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
MAX_DECODES_PER_FIELD = 8


def normalise_text(text: str) -> str:
    """Tag characters spelled out, NFKC, invisible characters removed, look-alike letters folded to Latin."""
    text = _TAG_RUN.sub(_untag, text)
    return unicodedata.normalize("NFKC", _INVISIBLE.sub("", text)).translate(_CONFUSABLES)


def _readable(raw: bytes) -> str | None:
    if len(raw) < 8:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    if printable < 0.95 * len(text):
        return None
    # Mostly letters, digits and spaces: ordinary text or a command, not binary noise.
    plain = sum(1 for ch in text if ch.isalnum() or ch in " \n\t./:-_")
    return text if plain >= 0.7 * len(text) else None


class TooManyDecodes(ValueError):
    """A field hides more base64 text than the scanner decodes. The caller
    reports scan_limit_exceeded rather than scan only the first few runs."""


def decode_base64_runs(text: str) -> list[str]:
    """Readable text hidden in base64 runs of ``text`` (one level).

    Raises TooManyDecodes when more than MAX_DECODES_PER_FIELD runs decode to
    readable text: stopping early would let the ninth run through unscanned.
    """
    out: list[str] = []
    for m in _BASE64_RUN.finditer(text):
        run = m.group(0)
        altchars = b"-_" if ("-" in run or "_" in run) else None
        padded = run + "=" * (-len(run) % 4)
        try:
            raw = base64.b64decode(padded, altchars=altchars, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _readable(raw)
        if decoded is not None:
            if len(out) >= MAX_DECODES_PER_FIELD:
                raise TooManyDecodes(f"a value hides more than {MAX_DECODES_PER_FIELD} base64-encoded texts")
            out.append(decoded)
    return out


_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


def text_variants(text: str) -> list[str]:
    """Other spellings of ``text`` worth scanning (empty when there are none).

    Raises TooManyDecodes (see decode_base64_runs).
    """
    variants: list[str] = []
    norm = normalise_text(text)
    if norm != text:
        variants.append(norm)
    if _PERCENT_ESCAPE.search(norm):
        decoded = unquote(norm)
        if decoded != norm:
            variants.append(decoded)
            again = normalise_text(decoded)
            if again != decoded:
                variants.append(again)
    for decoded in decode_base64_runs(norm):
        variants.append(decoded)
        again = normalise_text(decoded)
        if again != decoded:
            variants.append(again)
    return variants


def path_segments(path: str) -> list[str]:
    return [s for s in path.split(".") if s != ""] if path else []


def path_matches(path: str, patterns: Iterable[str]) -> bool:
    """True if ``path`` is at or below any pattern.

    A pattern without dots or wildcards names a key anywhere on the path
    ("page" matches "page", "results.0.page" and "page.text"). Other patterns
    are fnmatch globs over the dotted path and match the path or any prefix
    of it, so "results.*.html" covers "results.3.html.body".
    """
    segments = path_segments(path)
    lowered = [s.lower() for s in segments]
    for pattern in patterns:
        if not pattern:
            continue
        if "." not in pattern and not any(c in pattern for c in "*?["):
            if pattern.lower() in lowered:
                return True
            continue
        for i in range(1, len(segments) + 1):
            if fnmatch.fnmatchcase(".".join(segments[:i]), pattern):
                return True
    return False


def build_scan_input(
    data: Any,
    *,
    untrusted_paths: Iterable[str] = (),
    all_untrusted: bool = False,
    max_nodes: int = MAX_NODES,
    max_total_chars: int = MAX_TOTAL_CHARS,
) -> ScanInput:
    """Flatten ``data`` into (path, string) fields, iteratively, in document order."""
    untrusted_paths = list(untrusted_paths)
    out = ScanInput()
    nodes = 0
    chars = 0
    variant_chars = 0

    def is_untrusted(path: str) -> bool:
        return all_untrusted or (bool(untrusted_paths) and path_matches(path, untrusted_paths))

    def add_text(path: str, key: str, text: str) -> bool:
        """Add ``text`` and its variants as fields. False once a limit is hit."""
        nonlocal chars, variant_chars
        chars += len(text)
        if chars > max_total_chars:
            out.limit_exceeded = f"payload has more than {max_total_chars} characters of text"
            return False
        try:
            texts = [text, *text_variants(text)]
        except TooManyDecodes as exc:
            out.limit_exceeded = str(exc)
            return False
        # Variants are bounded separately: NFKC can expand a string many times
        # over, but ordinary normalised text must not halve the real limit.
        variant_chars += sum(len(t) for t in texts[1:])
        if variant_chars > VARIANT_ALLOWANCE * max_total_chars:
            out.limit_exceeded = "payload expands to too much text when normalised or decoded"
            return False
        untrusted = is_untrusted(path)
        for t in texts:
            out.fields.append(ScanField(path=path, key=key, value=t, untrusted=untrusted))
        return True

    stack: list[tuple[str, str, Any]] = [("", "", data)]
    while stack:
        path, key, value = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            out.limit_exceeded = f"payload has more than {max_nodes} values"
            break
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, (int, float)):
            out.numbers[path] = float(value)
            continue
        if isinstance(value, dict):
            items = list(value.items())
            # Keys are attacker-controlled text too (a schema property name, a
            # structured-output key), so every key is scanned as a field of its
            # own, with its variants. Its ScanField key is "" so a key named
            # "url" is not read as a bare host under a URL key.
            for k, _ in items:
                k = str(k)
                if not add_text(f"{path}.{k}" if path else k, "", k):
                    break
            if out.limit_exceeded:
                break
            for k, v in reversed(items):
                k = str(k)
                child = f"{path}.{k}" if path else k
                stack.append((child, k.lower(), v))
            continue
        if isinstance(value, (list, tuple)):
            for i in range(len(value) - 1, -1, -1):
                child = f"{path}.{i}" if path else str(i)
                stack.append((child, "", value[i]))
            continue
        text = value if isinstance(value, str) else str(value)
        if not add_text(path, key, text):
            break
    return out


# ---------------------------------------------------------------------------
# Rule base classes
# ---------------------------------------------------------------------------


class ThreatRule(ABC):
    """A detector. ``scan`` returns at most one ThreatMatch per rule."""

    name: str
    description: str

    @abstractmethod
    def scan(self, scan: ScanInput) -> list[ThreatMatch]:
        ...

    def check(self, event: dict) -> list[ThreatMatch]:
        """Convenience entry point: scan ``event["data"]``."""
        return self.scan(build_scan_input(event.get("data", {})))

    def redact(self, text: str) -> str:
        """Replace whatever this rule matches in ``text``. Default: no-op."""
        return text


@dataclass
class Pattern:
    regex: re.Pattern
    reason: str
    level: ThreatLevel
    untrusted_only: bool = False
    joined: bool = False  # also run on all fields joined together


def P(pattern: str, reason: str, level: ThreatLevel, *, flags: int = re.IGNORECASE,
      untrusted_only: bool = False, joined: bool = False) -> Pattern:
    return Pattern(re.compile(pattern, flags), reason, level, untrusted_only, joined)



def _after_first(keyword: str, body: str, separators: str) -> str:
    """Regex prefix for "``keyword``, then more text in the same segment".

    ``keyword[^\n]*X`` is quadratic: on a failed search the engine rescans the
    rest of the line from every occurrence of the keyword ("nc nc nc ...").
    This prefix starts only at a segment start (text start or just after one
    of ``separators``) and commits to the first keyword in the segment. The
    lookahead is atomic in Python's ``re``, so the engine cannot backtrack to
    a later keyword, and the first one leaves the longest tail, so a match
    exists exactly when the plain pattern would match. Linear time.
    """
    sep = re.escape(separators)
    return rf"(?:^|(?<=[{sep}]))(?=({body}*?{keyword}))\1"


class _Collector:
    """Merges hits for one rule into a single deduplicated ThreatMatch."""

    def __init__(self, rule_name: str, prefix: str) -> None:
        self.rule_name = rule_name
        self.prefix = prefix
        self.reasons: list[str] = []
        self.evidence: list[str] = []
        self.level: ThreatLevel | None = None
        self.first_pattern: str | None = None

    def add(self, reason: str, level: ThreatLevel, path: str, pattern: str | None = None) -> None:
        full = f"{self.prefix}{reason}"
        if full not in self.reasons:
            self.reasons.append(full)
        ev = path or "$"
        if ev not in self.evidence:
            self.evidence.append(ev)
        if self.level is None or SEVERITY_ORDER.index(level.value) > SEVERITY_ORDER.index(self.level.value):
            self.level = level
        if self.first_pattern is None:
            self.first_pattern = pattern

    def result(self) -> list[ThreatMatch]:
        if self.level is None:
            return []
        # Lead with the most severe reason so the one-line summary is the worst one.
        return [ThreatMatch(
            rule_name=self.rule_name,
            reason=self.reasons[0],
            threat_level=self.level,
            matched_pattern=self.first_pattern,
            reasons=list(self.reasons),
            evidence=list(self.evidence),
        )]


class RegexRule(ThreatRule):
    """A detector made of regex patterns, each with its own severity."""

    PATTERNS: list[Pattern] = []
    reason_prefix = ""

    def scan(self, scan: ScanInput) -> list[ThreatMatch]:
        col = _Collector(self.name, self.reason_prefix)
        hit_reasons: set[str] = set()
        # Severe patterns first so the headline reason is the worst one.
        ordered = sorted(self.PATTERNS, key=lambda p: -SEVERITY_ORDER.index(p.level.value))
        for f in scan.fields:
            for p in ordered:
                if p.untrusted_only and not f.untrusted:
                    continue
                if p.regex.search(f.value):
                    col.add(p.reason, p.level, f.path, p.regex.pattern)
                    hit_reasons.add(p.reason)
        # Strong patterns also run across field boundaries, so splitting an
        # instruction over two arguments does not hide it.
        joined_patterns = [p for p in ordered if p.joined and p.reason not in hit_reasons]
        if joined_patterns and len(scan.fields) > 1:
            text = " ".join(f.value for f in scan.fields)
            for p in joined_patterns:
                if p.regex.search(text):
                    col.add(p.reason, p.level, JOINED_PATH, p.regex.pattern)
        return col.result()

    def redact(self, text: str) -> str:
        for p in self.PATTERNS:
            text = p.regex.sub(f"[REDACTED:{self.name}]", text)
        return text


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

C, H, M, L = ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW


# Files that hold credentials. A tool description or output that names one is
# a tool-poisoning signal; together with a verb that reads or sends it, a strong one.
_CREDENTIAL_PATH = (
    r"(?:\.ssh/(?:id_(?:rsa|dsa|ecdsa|ed25519)\w*|authorized_keys|known_hosts|config)\b"
    r"|\.aws/(?:credentials|config)\b|\.config/gcloud\b|\.azure/\w|\.kube/config\b"
    r"|\.docker/config\.json|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b"
    r"|\.gnupg/|(?:\.cursor|\.claude|claude_desktop_config)[\w./-]*mcp\w*\.json|/etc/(?:shadow|sudoers)\b"
    r"|\bid_(?:rsa|ed25519)\b)"
)


class PromptInjectionRule(RegexRule):
    """Instruction overrides, role hijacking, jailbreak phrasing.

    Phrases that are only suspicious in content the agent did not write (for
    example "you are now ...", which is also ordinary English) fire only on
    untrusted paths, and at MEDIUM. Unambiguous overrides fire everywhere.
    """

    name = "prompt_injection"
    description = "Prompt injection attempt detected"
    reason_prefix = "Prompt injection: "

    PATTERNS = [
        P(r"\bignore\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:previous|prior|preceding|earlier)\s+(?:instructions|directions|prompts?|rules|messages)",
          "instruction override", C, joined=True),
        P(r"\bignore\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?above\b", "instruction override", C, joined=True),
        P(r"\bdisregard\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier)\b", "instruction override", C, joined=True),
        P(r"\bforget\s+(?:all\s+)?(?:of\s+)?(?:your|the|previous)\s+(?:previous\s+|prior\s+)?instructions\b", "instruction override", C, joined=True),
        P(r"\byou\s+are\s+now\s+(?:in\s+)?(?:DAN\b|an?\s+unrestricted|unrestricted|uncensored|jailbroken|developer\s+mode|no\s+longer\s+bound)",
          "role hijacking", C, joined=True),
        P(r"\bnew\s+instructions?\s*:", "instruction injection", H, joined=True),
        P(r"(?:^|\n)\s*system\s*:\s*you\b", "system prompt injection", C),
        P(r"<\s*/?\s*system\s*>", "XML tag injection", H),
        P(r"\]\s*\[\s*system\b", "bracket injection", H),
        P(r"\bADMIN\s+MODE\b", "privilege escalation via prompt", H, flags=0),
        P(r"\bjailbreak(?:ed|ing)?\b", "explicit jailbreak", H),
        P(r"\bdo\s+anything\s+now\b", "DAN pattern", C, joined=True),
        P(r"\bpretend\s+(?:that\s+)?you\s+(?:are|have)\s+(?:no|without)\s+(?:restrictions|rules|limits|guidelines)",
          "guardrail bypass", C, joined=True),
        P(r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered)", "guardrail bypass", C, joined=True),
        P(r"\b(?:enable|enter|activate|switch\s+to)\s+developer\s+mode\b", "developer mode exploit", C, joined=True),
        P(r"\b(?:reveal|print|show|repeat|output|leak)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)",
          "system prompt extraction", H, joined=True),
        # Weak signals: only in content the agent fetched or was handed.
        P(r"\byou\s+are\s+now\b", "role reassignment in untrusted content", M, untrusted_only=True),
        P(r"\bdeveloper\s+mode\b", "developer mode mention in untrusted content", M, untrusted_only=True),
        P(r"\b(?:assistant|AI|agent)\s*,?\s+(?:you\s+)?must\s+(?:now\s+)?(?:send|email|forward|post|upload|call)\b",
          "imperative aimed at the agent in untrusted content", M, untrusted_only=True),
        # Tool poisoning (Invariant Labs style): a description that tells the
        # model to read a credential file and keep quiet about it.
        P(r"\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:mention|tell|inform|notify|alert|warn|show|reveal|disclose)"
          r"\s+(?:(?:this|that|it|anything|any\s+of\s+this)\s+)?(?:to\s+)?the\s+user\b",
          "instruction to hide an action from the user", H, untrusted_only=True),
        P(r"\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+the\s+user\b",
          "instruction to hide an action from the user", H, untrusted_only=True),
        P(r"\b(?:hide|conceal|keep)\s+(?:this|that|it)\s+(?:secret\s+|hidden\s+)?from\s+the\s+user\b",
          "instruction to hide an action from the user", H, untrusted_only=True),
        P(r"\bthe\s+user\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|notice|find\s+out|be\s+told)\b",
          "instruction to hide an action from the user", H, untrusted_only=True),
        P(r"\b(?:read|cat|open|load|include|pass|send|attach|upload|copy|fetch|get)\b.{0,160}?" + _CREDENTIAL_PATH,
          "instruction to read a credential file", H, untrusted_only=True, flags=re.IGNORECASE | re.DOTALL),
        P(_CREDENTIAL_PATH, "credential file path in untrusted content", M, untrusted_only=True),
        P(r"<\s*/?\s*important\s*>", "<IMPORTANT> tag in untrusted content", M, untrusted_only=True),
    ]


class SensitiveDataLeakRule(RegexRule):
    """API keys, tokens, private keys and credential assignments."""

    name = "sensitive_data_leak"
    description = "Sensitive data exposed in agent output"
    reason_prefix = "Sensitive data leak: "

    PATTERNS = [
        P(r"\bsk-(?:proj-|ant-(?:api\d+-)?)?[A-Za-z0-9_\-]{20,}", "API key (sk-*)", H, flags=0),
        P(r"(?:api[_-]?key|apikey)[\"']?\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "API key assignment", H),
        P(r"(?:password|passwd|pwd)[\"']?\s*[=:]\s*['\"]?[^\s'\"*<>{}]{6,}", "password in output", H),
        P(r"(?:secret|token)[\"']?\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "secret/token assignment", H),
        P(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----", "private key", H),
        P(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key", H, flags=0),
        P(r"\bghp_[A-Za-z0-9]{36}\b", "GitHub personal token", H, flags=0),
        P(r"\bgho_[A-Za-z0-9]{36}\b", "GitHub OAuth token", H, flags=0),
        P(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", "GitHub fine-grained token", H, flags=0),
        P(r"\bdop_v1_[a-f0-9]{64}\b", "DigitalOcean token", H, flags=0),
        P(r"\bxox[bpas]-[A-Za-z0-9\-]{10,}", "Slack token", H, flags=0),
        P(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT token", H, flags=0),
    ]


EXFIL_DOMAINS = {
    "webhook.site": "webhook.site exfil endpoint",
    "requestbin.com": "requestbin exfil endpoint",
    "requestbin.net": "requestbin exfil endpoint",
    "requestcatcher.com": "requestcatcher exfil endpoint",
    "ngrok.io": "ngrok tunnel",
    "ngrok.app": "ngrok tunnel",
    "ngrok-free.app": "ngrok tunnel",
    "ngrok.dev": "ngrok tunnel",
    "burpcollaborator.net": "Burp Collaborator",
    "oastify.com": "Burp Collaborator",
    "interact.sh": "interactsh callback",
    "oast.fun": "interactsh callback",
    "oast.pro": "interactsh callback",
    "oast.live": "interactsh callback",
    "oast.site": "interactsh callback",
    "oast.online": "interactsh callback",
    "oast.me": "interactsh callback",
    "pipedream.net": "pipedream webhook",
    "hookbin.com": "hookbin exfil endpoint",
    "beeceptor.com": "beeceptor endpoint",
    "pastebin.com": "paste site",
    "transfer.sh": "file drop",
}

URL_IN_TEXT = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,15})://[^\s\"'<>`]+")
_BARE_EXFIL = re.compile(
    r"(?i)(?<![\w.-])((?:[a-z0-9-]+\.)*(?:" + "|".join(re.escape(d) for d in EXFIL_DOMAINS) + r"))(?![\w-])"
)
URL_KEYS = {
    "url", "uri", "href", "link", "endpoint", "host", "hostname", "target", "address",
    "src", "callback", "callback_url", "webhook", "webhook_url", "base_url", "server",
    "remote", "redirect", "redirect_uri", "redirect_url", "image", "image_url",
}
DANGEROUS_SCHEMES = {"file": "file:// URL", "gopher": "gopher:// URL", "dict": "dict:// URL",
                     "ldap": "ldap:// URL", "jar": "jar: URL", "netdoc": "netdoc: URL"}


@dataclass
class FoundURL:
    raw: str
    scheme: str
    host: str | None


def _split_url(raw: str) -> FoundURL | None:
    raw = raw.rstrip(".,;:!?)]}'\"")
    try:
        parts = urlsplit(raw)
        host = parts.hostname
    except ValueError:
        # Bad port or bracket: take the text between // and the next / ? #
        m = re.match(r"(?i)([a-z][a-z0-9+.\-]*)://(?:[^@/?#]*@)?(\[[^\]]*\]|[^/:?#]*)", raw)
        if not m:
            return None
        return FoundURL(raw, m.group(1).lower(), m.group(2).strip("[]").lower() or None)
    return FoundURL(raw, parts.scheme.lower(), (host or "").rstrip(".") or None)


def iter_urls(f: ScanField) -> Iterator[FoundURL]:
    """URLs in a field: scheme URLs anywhere, plus a bare host under a URL-like key."""
    seen = False
    for m in URL_IN_TEXT.finditer(f.value):
        u = _split_url(m.group(0))
        if u:
            seen = True
            yield u
    if not seen and f.key in URL_KEYS:
        value = f.value.strip()
        if value and " " not in value and len(value) < 2048:
            u = _split_url("http://" + value.lstrip("/"))
            if u:
                yield u


def exfil_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().rstrip(".")
    for domain, reason in EXFIL_DOMAINS.items():
        if host == domain or host.endswith("." + domain):
            return reason
    return None


_MD_IMAGE = re.compile(r"!\[[^\[\]]*\]\(\s*(https?://[^)\s]*)", re.IGNORECASE)
_IMG_TAG = re.compile(r"<img\b[^<>]*", re.IGNORECASE)
_IMG_SRC = re.compile(r"\bsrc\s*=\s*['\"]?(?=https?://)", re.IGNORECASE)
_IMG_URL = re.compile(r"[^'\" >]*")


def _has_query_value(url: str) -> bool:
    q = url.find("?")
    return q >= 0 and "=" in url[q + 1:]


def _image_exfil(text: str) -> list[str]:
    """Image URLs with a query string: a zero-click exfiltration channel when
    the agent's output is rendered as markdown or HTML.

    Written as a scan rather than one regex because "image, URL, then ? and =
    somewhere in it" backtracks quadratically when many image openers share
    one long URL-like run. Here each URL run is read once: a run that starts
    inside one already read is a suffix of it, so it cannot match if that
    one did not.
    """
    found: list[str] = []
    for m in _MD_IMAGE.finditer(text):  # finditer resumes after each URL run
        end = m.end(1)
        if (end < len(text) and text[end] == ")") and _has_query_value(m.group(1)):
            found.append("markdown image with query string (zero-click exfil channel)")
            break
    read_until = -1
    for tag in _IMG_TAG.finditer(text):
        hit = False
        for src in _IMG_SRC.finditer(text, tag.start(), tag.end()):
            start = src.end()
            if start < read_until:
                continue
            url = _IMG_URL.match(text, start)
            read_until = url.end()
            if _has_query_value(url.group(0)):
                hit = True
                break
        if hit:
            found.append("HTML image with query string (zero-click exfil channel)")
            break
    return found


class DataExfiltrationRule(ThreatRule):
    """Known exfiltration and callback hosts, raw-IP URLs, data uploads."""

    name = "data_exfiltration"
    description = "Data exfiltration attempt via external endpoint"

    UPLOAD_PATTERNS = [
        P(_after_first(r"\bcurl\b", r"[^\n|;]", "\n|;") + r"[^\n|;]*?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)(?=[\s=@'\"]|$)",
          "curl uploading data", H),
        P(_after_first(r"\bwget\b", r"[^\n|;]", "\n|;") + r"[^\n|;]*?--post-(?:data|file)\b", "wget posting data", H),
    ]

    def scan(self, scan: ScanInput) -> list[ThreatMatch]:
        col = _Collector(self.name, "Data exfiltration risk: ")
        for f in scan.fields:
            hosts_here: set[str] = set()
            for u in iter_urls(f):
                reason = exfil_domain(u.host)
                if reason:
                    col.add(reason, C, f.path, u.host)
                    hosts_here.add((u.host or "").lower())
                elif u.host and u.scheme in ("http", "https"):
                    if parse_ip_literal(u.host) is not None and classify_host_literal(u.host) is None:
                        col.add("raw IP address URL", H, f.path, u.host)
            for m in _BARE_EXFIL.finditer(f.value):
                if m.group(1).lower() not in hosts_here:
                    col.add(exfil_domain(m.group(1)) or "exfil endpoint", C, f.path, m.group(1))
            for p in self.UPLOAD_PATTERNS:
                if p.regex.search(f.value):
                    col.add(p.reason, p.level, f.path, p.regex.pattern)
            for reason in _image_exfil(f.value):
                col.add(reason, H, f.path, "image URL with a query string")
        return col.result()


class SSRFRule(ThreatRule):
    """URLs that point at loopback, private, link-local or metadata addresses.

    URLs are parsed (``urllib.parse``) and hosts classified with ``ipaddress``,
    so ``[::1]``, ``2130706433``, ``0x7f000001``, ``127.1`` and
    ``user@127.0.0.1`` are recognised. Hostnames are not resolved: DNS answers
    belong to the component that actually connects, which must pin the address
    it checked (see backend/netguard.py).
    """

    name = "ssrf"
    description = "Server-Side Request Forgery attempt"

    def scan(self, scan: ScanInput) -> list[ThreatMatch]:
        col = _Collector(self.name, "SSRF attempt: ")
        for f in scan.fields:
            for u in iter_urls(f):
                if u.scheme in DANGEROUS_SCHEMES:
                    col.add(DANGEROUS_SCHEMES[u.scheme], H, f.path, u.raw[:200])
                    continue
                if not u.host:
                    continue
                reason = classify_host_literal(u.host)
                if reason:
                    col.add(f"{reason} ({u.host})", H, f.path, u.raw[:200])
        return col.result()


class DangerousCodeRule(RegexRule):
    """Destructive commands, reverse shells, dynamic code execution."""

    name = "dangerous_code"
    description = "Dangerous command or code execution pattern"
    reason_prefix = "Dangerous operation: "

    PATTERNS = [
        P(r"\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*|--recursive|-r\s+-f|-f\s+-r)\b",
          "destructive file deletion", H),
        P(r"/dev/(?:tcp|udp)/", "reverse shell via /dev/tcp", C),
        P(r"\bmkfifo\b", "named pipe (reverse shell)", H),
        P(_after_first(r"\bnc\b", r"[^\n]", "\n") + r"[^\n]*\s-[a-z]*e\s", "netcat with -e (reverse shell)", C),
        P(r"\bchmod\s+(?:-R\s+)?777\b", "world-writable permissions", H),
        P(r"\bsudo\s+(?:-\S+\s+)*(?:rm|chmod|chown|dd|mkfs\S*|bash|sh|zsh|su|passwd|user(?:add|mod|del)|visudo|tee|cat\s+/etc/shadow)\b",
          "privilege escalation", H),
        P(_after_first(r"\b(?:curl|wget)\b", r"[^\n|]", "\n|") + r"[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", "download piped to shell", C),
        P(r"\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b", "piping to shell", H),
        P(r"\bos\.system\(", "Python os.system()", H),
        P(r"\bsubprocess\.(?:run|call|Popen|check_output)\(", "Python subprocess", H),
        P(r"(?<![\w.])eval\(", "eval() execution", H),
        P(r"(?<![\w.])exec\(", "exec() execution", H),
        P(r"__import__\(", "dynamic import", H),
        P(r"/etc/(?:passwd|shadow|sudoers)\b", "system file access", H),
        # ".env" as a file (cat .env, ./app/.env), not process.env or os.environ.
        P(r"(?<![\w$])\.env(?:\.[a-z]+)?(?![\w.(])", "environment file access", H),
        P(r"(?:\.\./){2,}|(?:\.\.\\){2,}", "path traversal", H),
        P(r"\bbase64\s+(?:-d|--decode)\b", "base64 decode (obfuscation)", H),
    ]


class InjectionRule(RegexRule):
    """SQL injection, XSS and shell command injection payloads.

    Plain ``UPDATE ... SET``, ``INSERT INTO`` and ``DELETE FROM`` are ordinary
    SQL, so only injection shapes (quote breakouts, tautologies, stacked
    statements) are flagged.
    """

    name = "injection"
    description = "Injection pattern detected in agent output"
    reason_prefix = "Injection pattern: "

    PATTERNS = [
        P(r"\bUNION\s+(?:ALL\s+)?SELECT\b", "SQL injection (UNION SELECT)", H),
        P(r"['\"]\s*;\s*(?:DROP|DELETE|ALTER|TRUNCATE|UPDATE|INSERT)\s", "SQL injection (chained)", H),
        P(r";\s*(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DROP\s+DATABASE)\b", "SQL injection (chained)", H),
        P(r"['\"]\s*(?:OR|AND)\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1\b", "SQL injection (tautology)", H),
        P(r"\b(?:OR|AND)\s+1\s*=\s*1\b", "SQL injection (tautology)", H),
        P(r"['\"]\s*(?:--\s|--$|/\*)", "SQL injection (comment terminator)", M),
        P(r"<\s*script\b[^>]*>", "XSS (script tag)", H),
        P(r"\bjavascript\s*:", "XSS (javascript: URI)", H),
        P(r"<[^<>]+\bon(?:load|error|click|mouseover|focus)\s*=", "XSS (event handler)", H),
        P(r";\s*(?:cat|ls|whoami|id|uname|nc|curl|wget)\b", "command injection", H),
        P(r"\$\(\s*(?:curl|wget|cat|whoami|id|uname|nc|bash|sh|base64|env|printenv)\b", "command substitution", H),
        P(r"`\s*(?:curl|wget|cat|whoami|id|uname|nc|bash|sh)\b[^`]*`", "command substitution (backticks)", H),
    ]


class UnauthorizedScopeRule(RegexRule):
    """Infrastructure mutations an agent should not trigger on its own."""

    name = "excessive_agency"
    description = "Agent action exceeds expected scope"
    reason_prefix = "Scope violation: "

    PATTERNS = [
        P(r"\b(?:execute|deploy|provision|create)\s+(?:the\s+|a\s+|new\s+)?(?:server|droplet|instance|cluster)s?\b", "real deployment attempt", M),
        P(r"\b(?:ssh|scp)\s+(?:-\S+\s+)*[\w.\-]+@", "remote server access", M),
        P(r"\bdoctl\s+\w+", "DigitalOcean CLI execution", M),
        P(r"\bterraform\s+(?:apply|destroy)\b", "infrastructure mutation", M),
        P(r"\bkubectl\s+(?:apply|delete|exec|scale|patch)\b", "Kubernetes mutation", M),
        P(r"\bdocker\s+(?:run|exec|push)\b", "container execution", M),
        P(r"\baws\s+(?:s3|ec2|iam|lambda)\s+\w+", "AWS CLI execution", M),
        P(r"\bgcloud\s+\w+\s+\w+", "GCP CLI execution", M),
    ]


class EvaluationManipulationRule(ThreatRule):
    """A very low top-level ``score``. An anomaly signal, not an OWASP category."""

    name = "eval_manipulation"
    description = "Anomalous evaluation score detected"

    def scan(self, scan: ScanInput) -> list[ThreatMatch]:
        score = scan.numbers.get("score")
        if score is None or score > 2:
            return []
        shown = int(score) if score == int(score) else score
        return [ThreatMatch(
            rule_name=self.name,
            reason=f"Critically low score ({shown}/10), possible adversarial input",
            threat_level=ThreatLevel.LOW,
            matched_pattern=f"score={shown}",
            evidence=["score"],
        )]


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

SCAN_LIMIT_RULE = "scan_limit_exceeded"
RULE_NAMES = [r.name for r in ALL_RULES] + [SCAN_LIMIT_RULE]
# Names the gateway and the policy engine give their own matches.
RESERVED_NAMES = {"policy", "tool_poisoning", "tool_definition_changed"}

# Extra detectors registered at runtime (model-based detectors, see
# backend/guardian/detectors). They run after the built-in rules.
_EXTRA_RULES: list[ThreatRule] = []
_env_loaded = False


def register_rule(rule: ThreatRule) -> None:
    """Add a detector to every default scan. Replaces one with the same name."""
    if rule.name in RULE_NAMES or rule.name in RESERVED_NAMES:
        raise ValueError(f"'{rule.name}' is a built-in detector name")
    unregister_rule(rule.name)
    _EXTRA_RULES.append(rule)


def unregister_rule(name: str) -> None:
    _EXTRA_RULES[:] = [r for r in _EXTRA_RULES if r.name != name]


def default_rules() -> list[ThreatRule]:
    """Built-in rules plus registered ones (loading GUARDIAN_MODEL_DETECTORS once)."""
    global _env_loaded
    if not _env_loaded:
        from backend.guardian.detectors import load_from_env
        load_from_env()  # raises on a bad entry; the next call tries again
        _env_loaded = True
    return ALL_RULES + _EXTRA_RULES


def known_detector_names() -> list[str]:
    """Names a policy may reference under ``detectors.rules``."""
    return RULE_NAMES + [r.name for r in default_rules() if r.name not in RULE_NAMES]


def detect(
    data: Any,
    *,
    untrusted_paths: Iterable[str] = (),
    all_untrusted: bool = False,
    rules: list[ThreatRule] | None = None,
    max_nodes: int = MAX_NODES,
    max_total_chars: int = MAX_TOTAL_CHARS,
) -> list[ThreatMatch]:
    """Run every detector over ``data``. One match per rule that fired."""
    scan = build_scan_input(
        data, untrusted_paths=untrusted_paths, all_untrusted=all_untrusted,
        max_nodes=max_nodes, max_total_chars=max_total_chars,
    )
    matches: list[ThreatMatch] = []
    for rule in rules or default_rules():
        matches.extend(rule.scan(scan))
    if scan.limit_exceeded:
        matches.append(ThreatMatch(
            rule_name=SCAN_LIMIT_RULE,
            reason=f"Payload too large to inspect fully: {scan.limit_exceeded}",
            threat_level=ThreatLevel.HIGH,
            evidence=["$"],
        ))
    return matches


def redact(data: Any, rule_names: Iterable[str], *, rules: list[ThreatRule] | None = None) -> Any:
    """Copy of ``data`` with the text matched by the named rules replaced.

    Regex rules replace what their patterns match; for ``ssrf`` and
    ``data_exfiltration`` the offending URLs are replaced.
    """
    wanted = set(rule_names)
    active = [r for r in (rules or ALL_RULES) if r.name in wanted]
    url_rules = wanted & {"ssrf", "data_exfiltration"}

    def url_repl(m: re.Match) -> str:
        u = _split_url(m.group(0))
        if not u:
            return m.group(0)
        bad = ("ssrf" in url_rules and (u.scheme in DANGEROUS_SCHEMES or bool(u.host and classify_host_literal(u.host)))) \
            or ("data_exfiltration" in url_rules and bool(exfil_domain(u.host)))
        return "[REDACTED:url]" if bad else m.group(0)

    def fix(text: str) -> str:
        for r in active:
            text = r.redact(text)
        if url_rules:
            text = URL_IN_TEXT.sub(url_repl, text)
            if "data_exfiltration" in url_rules:
                text = _BARE_EXFIL.sub("[REDACTED:url]", text)
        return text

    root: list[Any] = [None]
    stack: list[tuple[Any, Any, Any]] = [(data, root, 0)]
    while stack:
        src, parent, key = stack.pop()
        if isinstance(src, str):
            parent[key] = fix(src)
        elif isinstance(src, dict):
            new: dict = {}
            parent[key] = new
            for k, v in src.items():
                new[k] = None
                stack.append((v, new, k))
        elif isinstance(src, (list, tuple)):
            new_list: list = [None] * len(src)
            parent[key] = new_list
            for i, v in enumerate(src):
                stack.append((v, new_list, i))
        else:
            parent[key] = src
    return root[0]
