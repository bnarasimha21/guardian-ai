"""Single source of truth for OWASP mappings, labels and remediation text.

Two taxonomies are used:

* OWASP Top 10 for LLM Applications, 2025 edition (IDs ``LLM01`` to ``LLM10``).
* OWASP Top 10 for Agentic Applications, 2026 edition (IDs ``ASI01`` to ``ASI10``).

Every detector rule maps to at most one ID from each list. A rule that is not a
security weakness in either list (a low evaluation score, for example) carries no
OWASP tag instead of a made-up one. The frontend reads all of this from
``GET /api/taxonomy`` so labels are never duplicated in JavaScript or HTML.
"""

from __future__ import annotations

from dataclasses import dataclass

OWASP_LLM_EDITION = "OWASP Top 10 for LLM Applications 2025"
OWASP_AGENTIC_EDITION = "OWASP Top 10 for Agentic Applications 2026"

OWASP_LLM_2025: dict[str, dict[str, str]] = {
    "LLM01": {
        "label": "Prompt Injection",
        "description": "Crafted input (typed by a user or hidden in content the model reads) changes the model's behaviour, overrides its instructions or makes it act for the attacker.",
    },
    "LLM02": {
        "label": "Sensitive Information Disclosure",
        "description": "The application exposes secrets, credentials, personal data or confidential context through model output or tool calls.",
    },
    "LLM03": {
        "label": "Supply Chain",
        "description": "Compromised third-party models, datasets, plugins or tool servers introduce vulnerabilities or malicious behaviour.",
    },
    "LLM04": {
        "label": "Data and Model Poisoning",
        "description": "Training, fine-tuning or embedding data is manipulated to plant backdoors or bias.",
    },
    "LLM05": {
        "label": "Improper Output Handling",
        "description": "Model output is passed to browsers, shells, databases or HTTP clients without validation, enabling XSS, SQL injection, command execution or SSRF.",
    },
    "LLM06": {
        "label": "Excessive Agency",
        "description": "The agent has more tools, permissions or autonomy than its task needs, so a manipulated or mistaken model can take damaging actions.",
    },
    "LLM07": {
        "label": "System Prompt Leakage",
        "description": "Instructions or secrets placed in the system prompt are revealed to users or attackers.",
    },
    "LLM08": {
        "label": "Vector and Embedding Weaknesses",
        "description": "Weaknesses in how embeddings are generated, stored or retrieved allow injection, leakage or poisoning through retrieval.",
    },
    "LLM09": {
        "label": "Misinformation",
        "description": "The model produces false or misleading content that users or downstream systems trust.",
    },
    "LLM10": {
        "label": "Unbounded Consumption",
        "description": "Unrestricted inference or tool use lets an attacker exhaust resources, run up cost or extract the model.",
    },
}

OWASP_AGENTIC_2026: dict[str, dict[str, str]] = {
    "ASI01": {
        "label": "Agent Goal Hijack",
        "description": "Injected instructions in prompts, documents, tool output or messages redirect the agent's goals or plan.",
    },
    "ASI02": {
        "label": "Tool Misuse and Exploitation",
        "description": "The agent uses a legitimate tool in an unsafe way: wrong target, dangerous arguments, data sent somewhere it should not go.",
    },
    "ASI03": {
        "label": "Identity and Privilege Abuse",
        "description": "Credentials, tokens or delegated privileges are leaked, reused or escalated beyond what the task should allow.",
    },
    "ASI04": {
        "label": "Agentic Supply Chain Vulnerabilities",
        "description": "Tools, MCP servers, prompts or agents pulled in at runtime are malicious or change after they were trusted.",
    },
    "ASI05": {
        "label": "Unexpected Code Execution",
        "description": "The agent generates or runs code or shell commands that execute with real privileges.",
    },
    "ASI06": {
        "label": "Memory and Context Poisoning",
        "description": "Persistent memory or retrieved context is corrupted so later decisions are influenced.",
    },
    "ASI07": {
        "label": "Insecure Inter-Agent Communication",
        "description": "Messages between agents are spoofed, tampered with or not authenticated.",
    },
    "ASI08": {
        "label": "Cascading Failures",
        "description": "One faulty or compromised step propagates through connected agents and tools.",
    },
    "ASI09": {
        "label": "Human-Agent Trust Exploitation",
        "description": "The agent's apparent authority is used to mislead the human who approves or relies on it.",
    },
    "ASI10": {
        "label": "Rogue Agents",
        "description": "An agent acts outside its intended scope or against its principal's interests.",
    },
}


@dataclass(frozen=True)
class RuleInfo:
    name: str
    title: str
    owasp_llm: str
    owasp_agentic: str
    remediation: str


RULES: dict[str, RuleInfo] = {
    "prompt_injection": RuleInfo(
        "prompt_injection", "Prompt injection", "LLM01", "ASI01",
        "Treat fetched pages, emails, documents and tool results as data, not instructions. Keep them out of the "
        "system role, mark them as untrusted in the policy file, and require approval for high-impact tools that run "
        "after untrusted content was read.",
    ),
    "sensitive_data_leak": RuleInfo(
        "sensitive_data_leak", "Secret or credential in tool data", "LLM02", "ASI03",
        "Never put real credentials in prompts or tool arguments. Give tools scoped, short-lived tokens injected by "
        "the runtime, and redact patterns such as sk-*, AKIA* and private keys from output.",
    ),
    "data_exfiltration": RuleInfo(
        "data_exfiltration", "Data exfiltration endpoint", "LLM02", "ASI02",
        "Allowlist the hosts an agent may send data to and deny everything else. Known request-capture services "
        "(webhook.site, requestbin, ngrok, interactsh) are almost never legitimate tool targets.",
    ),
    "ssrf": RuleInfo(
        "ssrf", "Server-side request forgery", "LLM05", "ASI02",
        "Resolve the host before fetching and refuse loopback, private, link-local and cloud metadata addresses, "
        "including IPv6 and integer or hex IPv4 forms. Disable redirects or re-check every hop, and pin the IP you "
        "checked for the actual connection.",
    ),
    "dangerous_code": RuleInfo(
        "dangerous_code", "Dangerous command or code", "LLM05", "ASI05",
        "Run agent-generated code in a sandbox without credentials or network access, never with sudo. Prefer "
        "narrow tools over a general shell, and require approval for shell access.",
    ),
    "injection": RuleInfo(
        "injection", "SQL, XSS or command injection", "LLM05", "ASI02",
        "Use parameterised queries, encode model output before rendering it as HTML, and never interpolate model "
        "output into shell commands.",
    ),
    "excessive_agency": RuleInfo(
        "excessive_agency", "Infrastructure or remote action", "LLM06", "ASI02",
        "Grant the agent only the tools its task needs, and route deployments, infrastructure changes and remote "
        "access through a require_approval policy rule.",
    ),
    "eval_manipulation": RuleInfo(
        "eval_manipulation", "Anomalous evaluation score", "", "",
        "A very low evaluator score is an anomaly signal, not a vulnerability class. Check the input that produced "
        "it for adversarial content and confirm the evaluator itself is behaving.",
    ),
    "scan_limit_exceeded": RuleInfo(
        "scan_limit_exceeded", "Payload too large to scan", "LLM10", "",
        "GuardianAI stops walking a payload after a fixed number of nodes or characters and treats the rest as "
        "unscanned. Send smaller arguments, or raise the limits if the payload is legitimate.",
    ),
    "tool_poisoning": RuleInfo(
        "tool_poisoning", "Poisoned tool definition", "LLM01", "ASI04",
        "A tool's name, description or schema contains instructions aimed at the model. Remove the server or ask its "
        "maintainer to fix the definition; the gateway hides the tool until then.",
    ),
    "tool_definition_changed": RuleInfo(
        "tool_definition_changed", "Tool definition changed after approval", "LLM03", "ASI04",
        "The tool changed since it was pinned. Review the new definition, then re-approve it with "
        "`guardian-mcp pins approve <server.tool>`.",
    ),
    "policy": RuleInfo(
        "policy", "Policy decision", "LLM06", "ASI02",
        "The call matched a deny or require_approval rule in the policy file. Change the policy, the agent's "
        "identity, or the arguments if the call is legitimate.",
    ),
}


def rule_info(rule_name: str) -> RuleInfo | None:
    return RULES.get(rule_name)


def owasp_for_rule(rule_name: str) -> tuple[str, str]:
    """Return (owasp_llm, owasp_agentic) for a rule, or empty strings."""
    info = RULES.get(rule_name)
    if info is None:
        return "", ""
    return info.owasp_llm, info.owasp_agentic


def llm_label(owasp_id: str) -> str:
    return OWASP_LLM_2025.get(owasp_id, {}).get("label", "")


def agentic_label(owasp_id: str) -> str:
    return OWASP_AGENTIC_2026.get(owasp_id, {}).get("label", "")


def taxonomy_payload() -> dict:
    """JSON served by GET /api/taxonomy."""
    return {
        "owasp_llm": {"edition": OWASP_LLM_EDITION, "items": OWASP_LLM_2025},
        "owasp_agentic": {"edition": OWASP_AGENTIC_EDITION, "items": OWASP_AGENTIC_2026},
        "rules": {
            name: {
                "title": info.title,
                "owasp_llm": info.owasp_llm,
                "owasp_agentic": info.owasp_agentic,
                "remediation": info.remediation,
            }
            for name, info in RULES.items()
        } | _registered_detectors(),
    }


def _registered_detectors() -> dict:
    """Model detectors registered at runtime, described the same way."""
    from .rules import default_rules  # late import: rules imports this module

    out = {}
    for rule in default_rules():
        det = getattr(rule, "detector", None)
        if det is not None and rule.name not in RULES:
            out[rule.name] = {
                "title": det.description or det.name,
                "owasp_llm": det.owasp_llm,
                "owasp_agentic": det.owasp_agentic,
                "remediation": "Flagged by a model-based detector. Review the input it scored and the "
                               "detector's threshold.",
            }
    return out
