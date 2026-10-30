"""Detection scorecard: run the labelled corpus through the real policy engine.

    python evals/run.py                      # write evals/report.md and evals/report.json
    python evals/run.py --check              # also compare with evals/baseline.json, exit 1 on regression
    python evals/run.py --write-baseline     # accept the current numbers as the new baseline
    python evals/run.py --model-detector my_pkg.detectors:MyModel   # score a ModelDetector too

Everything runs in process with no network access: call-phase records go
through ``policy.engine.evaluate`` exactly as ``POST /api/check`` does,
result-phase records through the result rules the MCP gateway applies to tool
output, tool definitions through the gateway's poisoning screen, and
definition changes through the gateway's pin store.

Corpus records (``evals/corpus/*.jsonl``, one JSON object per line)::

    {"id": "pi-direct-01", "tool": "chat.reply", "arguments": {...},
     "label": "attack" | "benign", "category": "...",
     "owasp_llm": "LLM01", "owasp_agentic": "ASI01",
     "expected_rules": ["prompt_injection"], "source": "...", "licence": "...",
     "phase": "call" | "result" | "tool_definition" | "tool_definition_change",   # default call
     "agent": "ops",                                                             # optional
     "expand": {"path": "text", "repeat": "...", "times": N}                     # optional, builds big payloads
               or {"path": "items", "list_of": "x", "times": N}}

Metrics, per detector rule R:

* TP: attack records that expect R and where R fired. FN: expected, did not fire.
* FP: benign records where R fired. (R firing on an attack record that did
  not expect it is listed as "extra", not counted as a false positive.)
* precision = TP / (TP + FP), recall = TP / (TP + FN),
  false-positive rate = FP / number of benign records.

Decision level: an attack is "detected" when any of its expected rules fired
and "stopped" when the outcome was not a plain allow (call: deny or
require_approval; result: deny or redact; definitions: hidden). A benign
record is "flagged" when any detector fired and "blocked" when it was stopped.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.events.models import SEVERITY_ORDER  # noqa: E402
from backend.guardian.detectors import load_from_env  # noqa: E402
from backend.guardian.rules import known_detector_names  # noqa: E402
from backend.guardian.schema import ToolCall  # noqa: E402
from backend.guardian.taxonomy import owasp_for_rule  # noqa: E402
from backend.mcp_gateway.pins import PinStore, definition_sha256  # noqa: E402
from backend.mcp_gateway.proxy import screen_definition  # noqa: E402
from backend.policy import engine  # noqa: E402
from backend.policy.loader import PolicyStore  # noqa: E402

EVALS = Path(__file__).resolve().parent
DEFAULT_CORPUS = EVALS / "corpus"
DEFAULT_POLICY = ROOT / "policies" / "default.yaml"
BASELINE = EVALS / "baseline.json"
CRITICAL_RULES = ("prompt_injection", "data_exfiltration", "dangerous_code")
PHASES = ("call", "result", "tool_definition", "tool_definition_change")
GATEWAY_RULES = ("tool_poisoning", "tool_definition_changed")
REQUIRED = ("id", "tool", "arguments", "label", "category", "owasp_llm", "owasp_agentic",
            "expected_rules", "source", "licence")
NONE = "(none)"


class CorpusError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_corpus(directory: Path) -> list[dict]:
    files = sorted(Path(directory).glob("*.jsonl"))
    if not files:
        raise CorpusError(f"no *.jsonl files in {directory}")
    known = set(known_detector_names()) | set(GATEWAY_RULES)
    records: list[dict] = []
    seen: set[str] = set()
    for path in files:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            where = f"{path.name}:{n}"
            try:
                rec = json.loads(line)
            except ValueError as exc:
                raise CorpusError(f"{where}: not JSON: {exc}") from exc
            missing = [k for k in REQUIRED if k not in rec]
            if missing:
                raise CorpusError(f"{where}: missing {', '.join(missing)}")
            if rec["id"] in seen:
                raise CorpusError(f"{where}: duplicate id {rec['id']}")
            seen.add(rec["id"])
            if rec["label"] not in ("attack", "benign"):
                raise CorpusError(f"{where}: label must be attack or benign")
            if rec.get("phase", "call") not in PHASES:
                raise CorpusError(f"{where}: phase must be one of {', '.join(PHASES)}")
            if rec["label"] == "attack" and not rec["expected_rules"]:
                raise CorpusError(f"{where}: an attack record needs expected_rules")
            if rec["label"] == "benign" and rec["expected_rules"]:
                raise CorpusError(f"{where}: a benign record must not expect rules")
            unknown = [r for r in rec["expected_rules"] if r not in known]
            if unknown:
                raise CorpusError(f"{where}: unknown rule(s) {', '.join(unknown)}")
            rec["_file"] = path.name
            records.append(rec)
    return records


def materialise(rec: dict) -> Any:
    """The record's arguments, with any ``expand`` applied (for oversized payloads)."""
    args = json.loads(json.dumps(rec["arguments"]))
    spec = rec.get("expand")
    if spec:
        if "repeat" in spec:
            args[spec["path"]] = str(spec["repeat"]) * int(spec["times"])
        elif "list_of" in spec:
            args[spec["path"]] = [spec["list_of"]] * int(spec["times"])
        else:
            raise CorpusError(f"{rec['id']}: expand needs 'repeat' or 'list_of'")
    return args


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


@dataclass
class Outcome:
    id: str
    label: str
    phase: str
    category: str
    file: str
    owasp_llm: str
    owasp_agentic: str
    expected: list[str]
    fired: list[str] = field(default_factory=list)
    top_rule: str = ""
    top_owasp_llm: str = ""
    top_owasp_agentic: str = ""
    effect: str = ""
    rule_id: str = ""
    stopped: bool = False
    by_detector: bool = False

    @property
    def detected(self) -> bool:
        return any(r in self.fired for r in self.expected)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "phase": self.phase, "category": self.category,
            "expected_rules": self.expected, "fired": self.fired, "effect": self.effect,
            "rule_id": self.rule_id, "stopped": self.stopped, "detected": self.detected if self.expected else None,
        }


def _top(matches) -> tuple[str, str, str]:
    if not matches:
        return "", "", ""
    m = max(matches, key=lambda x: SEVERITY_ORDER.index(x.threat_level.value))
    return m.rule_name, m.owasp_llm, m.owasp_agentic


def run_record(rec: dict, loaded, block_threshold: str, pin_dir: Path) -> Outcome:
    phase = rec.get("phase", "call")
    out = Outcome(rec["id"], rec["label"], phase, rec["category"], rec["_file"],
                  rec["owasp_llm"], rec["owasp_agentic"], list(rec["expected_rules"]))
    args = materialise(rec)
    agent = rec.get("agent", "")
    call = ToolCall(name=rec["tool"], arguments=args if phase == "call" else {}, agent_id=agent, agent_name=agent)

    if phase == "call":
        d = engine.evaluate(loaded, call, phase="call", block_threshold=block_threshold)
        out.fired = sorted({m.rule_name for m in d.matches})
        out.top_rule, out.top_owasp_llm, out.top_owasp_agentic = _top(d.matches)
        out.effect, out.rule_id = d.effect, d.rule_id
        out.stopped = d.effect in ("deny", "require_approval")
        out.by_detector = out.stopped and bool(d.deciding_detectors)
    elif phase == "result":
        d = engine.evaluate(loaded, call, phase="result", result=args, block_threshold=block_threshold)
        out.fired = sorted({m.rule_name for m in d.matches})
        out.top_rule, out.top_owasp_llm, out.top_owasp_agentic = _top(d.matches)
        out.effect, out.rule_id = d.effect, d.rule_id
        out.stopped = d.effect in ("deny", "redact")
        out.by_detector = out.stopped
    elif phase == "tool_definition":
        verdict, poisoned = screen_definition(loaded, call, args, block_threshold)
        fired = {m.rule_name for m in verdict.matches}
        if poisoned:
            fired.add("tool_poisoning")
            out.top_rule = "tool_poisoning"
            out.top_owasp_llm, out.top_owasp_agentic = owasp_for_rule("tool_poisoning")
        else:
            out.top_rule, out.top_owasp_llm, out.top_owasp_agentic = _top(verdict.matches)
        out.fired = sorted(fired)
        out.effect = "hidden" if poisoned else "listed"
        out.rule_id = "tool_poisoning" if poisoned else verdict.rule_id
        out.stopped = out.by_detector = poisoned
    else:  # tool_definition_change: pin "before", then list "after"
        pins = PinStore(pin_dir / f"{rec['id']}.json")
        pins.check(rec["tool"], definition_sha256(args["before"]))
        changed = pins.check(rec["tool"], definition_sha256(args["after"])) == "changed"
        if changed:
            out.fired = ["tool_definition_changed"]
            out.top_rule = "tool_definition_changed"
            out.top_owasp_llm, out.top_owasp_agentic = owasp_for_rule("tool_definition_changed")
        out.effect = "hidden" if changed else "listed"
        out.rule_id = "pin" if changed else "match"
        out.stopped = out.by_detector = changed
    return out


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def score(outcomes: list[Outcome]) -> dict:
    attacks = [o for o in outcomes if o.label == "attack"]
    benign = [o for o in outcomes if o.label == "benign"]

    rules = sorted({r for o in outcomes for r in o.expected} | {r for o in outcomes for r in o.fired})
    per_rule = {}
    for r in rules:
        tp = sum(1 for o in attacks if r in o.expected and r in o.fired)
        fn = sum(1 for o in attacks if r in o.expected and r not in o.fired)
        fp = sum(1 for o in benign if r in o.fired)
        extra = sum(1 for o in attacks if r not in o.expected and r in o.fired)
        llm, agentic = owasp_for_rule(r)
        per_rule[r] = {
            "owasp_llm": llm, "owasp_agentic": agentic,
            "attacks": tp + fn, "tp": tp, "fn": fn, "fp": fp, "extra_on_attacks": extra,
            "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, len(benign)),
        }

    def confusion(true_key: str, pred_key: str) -> dict:
        table: dict[str, Counter] = defaultdict(Counter)
        for o in outcomes:
            row = "benign" if o.label == "benign" else (getattr(o, true_key) or NONE)
            if not o.fired:
                col = "not flagged"
            else:
                col = getattr(o, pred_key) or NONE
            table[row][col] += 1
        return {row: dict(sorted(cols.items())) for row, cols in sorted(table.items())}

    by_owasp: dict[str, dict] = {}
    for o in attacks:
        key = o.owasp_llm or NONE
        slot = by_owasp.setdefault(key, {"attacks": 0, "detected": 0, "stopped": 0})
        slot["attacks"] += 1
        slot["detected"] += o.detected
        slot["stopped"] += o.stopped
    for slot in by_owasp.values():
        slot["detection_rate"] = _ratio(slot["detected"], slot["attacks"])

    summary = {
        "records": len(outcomes),
        "attacks": len(attacks),
        "benign": len(benign),
        "benign_share": _ratio(len(benign), len(outcomes)),
        "attack_detection_rate": _ratio(sum(o.detected for o in attacks), len(attacks)),
        "attack_stopped_rate": _ratio(sum(o.stopped for o in attacks), len(attacks)),
        "attack_stopped_by_detector_rate": _ratio(sum(o.by_detector for o in attacks), len(attacks)),
        "benign_flagged_rate": _ratio(sum(bool(o.fired) for o in benign), len(benign)),
        "benign_blocked_rate": _ratio(sum(o.stopped for o in benign), len(benign)),
    }
    return {
        "summary": summary,
        "rules": per_rule,
        "owasp_llm": dict(sorted(by_owasp.items())),
        "confusion_owasp_llm": confusion("owasp_llm", "top_owasp_llm"),
        "confusion_owasp_agentic": confusion("owasp_agentic", "top_owasp_agentic"),
        "misses": [o.to_dict() for o in attacks if not o.detected],
        "false_positives": [o.to_dict() for o in benign if o.fired or o.stopped],
        "phases": dict(sorted(Counter(o.phase for o in outcomes).items())),
        "files": dict(sorted(Counter(o.file for o in outcomes).items())),
    }


def evaluate_corpus(corpus_dir: Path = DEFAULT_CORPUS, policy_file: Path = DEFAULT_POLICY,
                    block_threshold: str = "high") -> tuple[dict, list[Outcome]]:
    records = load_corpus(corpus_dir)
    loaded = PolicyStore(policy_file).get()
    with tempfile.TemporaryDirectory(prefix="guardian-evals-") as tmp:
        outcomes = [run_record(r, loaded, block_threshold, Path(tmp)) for r in records]
    report = score(outcomes)
    report["policy"] = {"file": _rel(policy_file), "sha256": loaded.sha256, "block_threshold": block_threshold}
    report["records"] = [o.to_dict() for o in outcomes]
    return report, outcomes


def _rel(p: Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(ROOT))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v * 100:.1f}%"


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# GuardianAI detection scorecard",
        "",
        "Generated by `python evals/run.py` from `evals/corpus/*.jsonl` against "
        f"`{report['policy']['file']}` (sha256 `{report['policy']['sha256'][:12]}`, block threshold "
        f"`{report['policy']['block_threshold']}`). Every record runs in process through the same policy engine as "
        "`POST /api/check` and the MCP gateway; nothing touches the network.",
        "",
        "The corpus is small and partly written by the same people who wrote the detectors, so these numbers "
        "describe regression coverage, not real-world accuracy.",
        "",
        "## Summary",
        "",
        "| Measure | Value |",
        "| --- | --- |",
        f"| Records | {s['records']} ({s['attacks']} attack, {s['benign']} benign, {_pct(s['benign_share'])} benign) |",
        f"| Attacks detected (an expected rule fired) | {_pct(s['attack_detection_rate'])} |",
        f"| Attacks stopped (deny, approval, redact or hidden) | {_pct(s['attack_stopped_rate'])} |",
        f"| Attacks stopped because a detector fired | {_pct(s['attack_stopped_by_detector_rate'])} |",
        f"| Benign records flagged by any detector | {_pct(s['benign_flagged_rate'])} |",
        f"| Benign records blocked | {_pct(s['benign_blocked_rate'])} |",
        "",
        "## Per rule",
        "",
        "| Rule | OWASP LLM | OWASP Agentic | Attacks | TP | FN | FP | Precision | Recall | FP rate |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, r in report["rules"].items():
        lines.append(f"| `{name}` | {r['owasp_llm'] or '-'} | {r['owasp_agentic'] or '-'} | {r['attacks']} | {r['tp']} | "
                     f"{r['fn']} | {r['fp']} | {_pct(r['precision'])} | {_pct(r['recall'])} | "
                     f"{_pct(r['false_positive_rate'])} |")
    lines += ["", "FP counts benign records only. A rule firing on an attack it was not labelled for is not "
              "counted against it.", "", "## By OWASP LLM category", "",
              "| Category | Attacks | Detected | Stopped | Detection rate |", "| --- | --- | --- | --- | --- |"]
    for cat, v in report["owasp_llm"].items():
        lines.append(f"| {cat} | {v['attacks']} | {v['detected']} | {v['stopped']} | {_pct(v['detection_rate'])} |")

    for title, key in (("OWASP LLM confusion", "confusion_owasp_llm"),
                       ("OWASP Agentic confusion", "confusion_owasp_agentic")):
        table = report[key]
        cols = sorted({c for row in table.values() for c in row})
        lines += ["", f"## {title}", "",
                  "Rows are the labelled category, columns the category of the most severe match "
                  "(\"not flagged\" when nothing fired).", "",
                  "| Labelled \\ Predicted | " + " | ".join(cols) + " |",
                  "| --- | " + " | ".join("---" for _ in cols) + " |"]
        for row, counts in table.items():
            lines.append(f"| {row} | " + " | ".join(str(counts.get(c, 0)) for c in cols) + " |")

    lines += ["", f"## Missed attacks ({len(report['misses'])})", ""]
    if report["misses"]:
        lines += ["| Record | Category | Expected | Fired | Outcome |", "| --- | --- | --- | --- | --- |"]
        for m in report["misses"]:
            lines.append(f"| `{m['id']}` | {m['category']} | {', '.join(m['expected_rules'])} | "
                         f"{', '.join(m['fired']) or '-'} | {m['effect']} ({m['rule_id']}) |")
    else:
        lines.append("None.")
    lines += ["", f"## Benign records flagged or blocked ({len(report['false_positives'])})", ""]
    if report["false_positives"]:
        lines += ["| Record | Category | Fired | Outcome |", "| --- | --- | --- | --- |"]
        for m in report["false_positives"]:
            lines.append(f"| `{m['id']}` | {m['category']} | {', '.join(m['fired']) or '-'} | "
                         f"{m['effect']} ({m['rule_id']}) |")
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def write_reports(report: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                         encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")


# ---------------------------------------------------------------------------
# Baseline gate
# ---------------------------------------------------------------------------


def baseline_from(report: dict) -> dict:
    return {
        "critical_rule_recall": {r: report["rules"].get(r, {}).get("recall") for r in CRITICAL_RULES},
        "benign_flagged_rate": report["summary"]["benign_flagged_rate"],
        "benign_blocked_rate": report["summary"]["benign_blocked_rate"],
    }


def compare(report: dict, baseline: dict) -> list[str]:
    """Regressions against the baseline (empty list = pass)."""
    problems = []
    now = baseline_from(report)
    for rule, was in baseline.get("critical_rule_recall", {}).items():
        is_ = now["critical_rule_recall"].get(rule)
        if was is not None and (is_ is None or is_ < was):
            problems.append(f"recall for {rule} dropped: {_pct(was)} -> {_pct(is_)}")
    for key in ("benign_flagged_rate", "benign_blocked_rate"):
        was, is_ = baseline.get(key), now[key]
        if was is not None and is_ is not None and is_ > was:
            problems.append(f"{key.replace('_', ' ')} rose: {_pct(was)} -> {_pct(is_)}")
    return problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score GuardianAI's detectors on the labelled corpus")
    p.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    p.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    p.add_argument("--block-threshold", default="high", choices=["low", "medium", "high", "critical"])
    p.add_argument("--out", type=Path, default=EVALS, help="where report.md and report.json go")
    p.add_argument("--baseline", type=Path, default=BASELINE)
    p.add_argument("--check", action="store_true", help="exit 1 if a metric regressed against the baseline")
    p.add_argument("--write-baseline", action="store_true", help="save the current numbers as the baseline")
    p.add_argument("--model-detector", action="append", default=[], metavar="MODULE:ATTR",
                   help="register a ModelDetector before scoring (repeatable)")
    args = p.parse_args(argv)

    try:
        for spec in args.model_detector:
            load_from_env(spec)
        report, _ = evaluate_corpus(args.corpus, args.policy, args.block_threshold)
    except (CorpusError, ValueError) as exc:
        print(f"evals: {exc}", file=sys.stderr)
        return 2
    write_reports(report, args.out)
    s = report["summary"]
    print(f"{s['records']} records: attacks detected {_pct(s['attack_detection_rate'])}, "
          f"stopped {_pct(s['attack_stopped_rate'])}; benign flagged {_pct(s['benign_flagged_rate'])}, "
          f"blocked {_pct(s['benign_blocked_rate'])}. Report: {_rel(args.out / 'report.md')}")

    if args.write_baseline:
        args.baseline.write_text(json.dumps(baseline_from(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"baseline written to {_rel(args.baseline)}")
    if args.check:
        if not args.baseline.exists():
            print(f"evals: no baseline at {args.baseline}; run with --write-baseline first", file=sys.stderr)
            return 2
        problems = compare(report, json.loads(args.baseline.read_text(encoding="utf-8")))
        if problems:
            print("REGRESSION against the baseline:", file=sys.stderr)
            for line in problems:
                print(f"  - {line}", file=sys.stderr)
            return 1
        print("no regression against the baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
