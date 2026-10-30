"""Issue 5: the labelled corpus, the scorecard and the CI regression gate."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import types
from pathlib import Path

import pytest

from backend.events.models import ThreatLevel
from backend.guardian import rules as rules_mod
from backend.guardian.detectors import ModelDetector, unregister_model_detector
from backend.guardian.taxonomy import RULES

ROOT = Path(__file__).resolve().parent.parent
EVALS = ROOT / "evals"


def _load_run():
    spec = importlib.util.spec_from_file_location("guardian_evals_run", EVALS / "run.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look the module up by name
    spec.loader.exec_module(mod)
    return mod


run = _load_run()


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the eval harness tried to open a network connection")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.fixture(scope="module")
def corpus():
    return {r["id"]: r for r in run.load_corpus(run.DEFAULT_CORPUS)}


# -- corpus shape -------------------------------------------------------------


def test_corpus_size_and_balance(corpus):
    records = list(corpus.values())
    benign = [r for r in records if r["label"] == "benign"]
    assert len(records) >= 150
    assert len(benign) / len(records) >= 0.40


def test_every_owasp_category_used_by_a_rule_is_represented(corpus):
    attacks = [r for r in corpus.values() if r["label"] == "attack"]
    have_llm = {r["owasp_llm"] for r in attacks}
    have_agentic = {r["owasp_agentic"] for r in attacks}
    want_llm = {info.owasp_llm for name, info in RULES.items() if name != "policy" and info.owasp_llm}
    want_agentic = {info.owasp_agentic for name, info in RULES.items() if name != "policy" and info.owasp_agentic}
    assert want_llm <= have_llm, want_llm - have_llm
    assert want_agentic <= have_agentic, want_agentic - have_agentic
    # Every detector rule has at least one attack labelled for it.
    expected = {rule for r in attacks for rule in r["expected_rules"]}
    assert set(rules_mod.RULE_NAMES) | {"tool_poisoning", "tool_definition_changed"} <= expected


def test_records_carry_source_and_licence(corpus):
    for r in corpus.values():
        assert r["source"].strip() and r["licence"].strip(), r["id"]
        if "paraphrase" in r["source"]:
            assert "paraphrase" in r["licence"], r["id"]


def test_issue_regressions_are_pinned_in_the_corpus(corpus):
    texts = {json.dumps(r["arguments"]): r for r in corpus.values()}

    def find(fragment):
        hits = [r for k, r in texts.items() if fragment in k]
        assert hits, fragment
        return hits[0]

    for fp in ("process.env.API_URL", "You are now connected to the planner", "Run sudo apt install"):
        assert find(fp)["label"] == "benign"
    for miss in ("http://[::1]:8080/admin", "http://2130706433/", "http://0x7f000001/"):
        assert find(miss)["label"] == "attack"


def test_loader_rejects_bad_records(tmp_path):
    good = {"id": "a", "tool": "chat.reply", "arguments": {}, "label": "benign", "category": "x",
            "owasp_llm": "", "owasp_agentic": "", "expected_rules": [], "source": "s", "licence": "l"}
    cases = [
        {**good, "label": "maybe"},
        {**good, "expected_rules": ["prompt_injection"]},
        {**good, "label": "attack"},
        {**good, "label": "attack", "expected_rules": ["no_such_rule"]},
        {**good, "phase": "later"},
        {k: v for k, v in good.items() if k != "licence"},
    ]
    for i, bad in enumerate(cases):
        d = tmp_path / f"c{i}"
        d.mkdir()
        (d / "x.jsonl").write_text(json.dumps(bad) + "\n")
        with pytest.raises(run.CorpusError):
            run.load_corpus(d)
    d = tmp_path / "dup"
    d.mkdir()
    (d / "x.jsonl").write_text(json.dumps(good) + "\n" + json.dumps(good) + "\n")
    with pytest.raises(run.CorpusError):
        run.load_corpus(d)


# -- the scorecard -------------------------------------------------------------


def test_report_generated_offline_and_deterministic(tmp_path, no_network, capsys):
    assert run.main(["--out", str(tmp_path / "a")]) == 0
    assert run.main(["--out", str(tmp_path / "b")]) == 0
    a_json = (tmp_path / "a" / "report.json").read_text()
    assert a_json == (tmp_path / "b" / "report.json").read_text()
    assert (tmp_path / "a" / "report.md").read_text() == (tmp_path / "b" / "report.md").read_text()
    report = json.loads(a_json)
    assert report["summary"]["records"] >= 150
    for name in ("prompt_injection", "ssrf", "sensitive_data_leak", "tool_poisoning"):
        r = report["rules"][name]
        assert {"precision", "recall", "false_positive_rate", "tp", "fn", "fp"} <= set(r)
    assert "LLM01" in report["confusion_owasp_llm"] and "benign" in report["confusion_owasp_llm"]
    md = (tmp_path / "a" / "report.md").read_text()
    for heading in ("## Per rule", "## OWASP LLM confusion", "## OWASP Agentic confusion", "## Missed attacks"):
        assert heading in md


def test_committed_report_matches_the_code(tmp_path):
    """evals/report.json in the repo is what the current code and corpus produce."""
    assert run.main(["--out", str(tmp_path)]) == 0
    assert (tmp_path / "report.json").read_text() == (EVALS / "report.json").read_text(), \
        "re-run `python evals/run.py` and commit evals/report.*"


def test_baseline_check_passes_on_current_code(tmp_path):
    assert run.main(["--out", str(tmp_path), "--check"]) == 0


def test_check_fails_on_a_regressed_pattern(tmp_path, monkeypatch, capsys):
    """CI gate: dropping the instruction-override pattern must fail --check."""
    rule = next(r for r in rules_mod.ALL_RULES if r.name == "prompt_injection")
    weakened = [p for p in rule.PATTERNS if p.reason != "instruction override"]
    assert len(weakened) < len(rule.PATTERNS)
    monkeypatch.setattr(rule, "PATTERNS", weakened)
    assert run.main(["--out", str(tmp_path), "--check"]) == 1
    err = capsys.readouterr().err
    assert "recall for prompt_injection dropped" in err


def test_check_fails_when_false_positives_rise(tmp_path, monkeypatch, capsys):
    import re
    rule = next(r for r in rules_mod.ALL_RULES if r.name == "dangerous_code")
    noisy = rules_mod.Pattern(re.compile(r"\bthe\b", re.I), "overbroad", ThreatLevel.HIGH)
    monkeypatch.setattr(rule, "PATTERNS", [*rule.PATTERNS, noisy])
    assert run.main(["--out", str(tmp_path), "--check"]) == 1
    err = capsys.readouterr().err
    assert "benign flagged rate rose" in err and "benign blocked rate rose" in err


def test_model_detector_flag_scores_a_classifier(tmp_path, monkeypatch):
    class Toy(ModelDetector):
        name = "toy_leet_model"
        description = "Toy leetspeak injection classifier"
        owasp_llm = "LLM01"
        owasp_agentic = "ASI01"
        threshold = 0.5
        level = ThreatLevel.HIGH

        def score(self, text: str) -> float:
            return 1.0 if "1gn0re" in text else 0.0

    mod = types.ModuleType("toy_eval_detector")
    mod.Toy = Toy
    monkeypatch.setitem(sys.modules, "toy_eval_detector", mod)
    try:
        assert run.main(["--out", str(tmp_path), "--model-detector", "toy_eval_detector:Toy"]) == 0
    finally:
        unregister_model_detector("toy_leet_model")
    report = json.loads((tmp_path / "report.json").read_text())
    toy = report["rules"]["toy_leet_model"]
    assert toy["fp"] == 0 and toy["extra_on_attacks"] == 1
    leet = next(r for r in report["records"] if r["id"] == "pi-obfuscated-leetspeak")
    assert "toy_leet_model" in leet["fired"]


# -- 20 records through the real HTTP path -----------------------------------------

HTTP_SUBSET = [
    # attacks
    "pi-direct-01", "pi-obfuscated-zero-width", "pi-obfuscated-homoglyph", "pi-obfuscated-base64",
    "pi-indirect-03", "ssrf-02", "ssrf-03", "ssrf-04", "secret-01", "code-07",
    # benign
    "benign-nearmiss-01", "benign-nearmiss-02", "benign-nearmiss-03", "benign-nearmiss-04",
    "benign-travel-01", "benign-travel-04", "benign-architect-01", "benign-deadstartups-02",
    "benign-nearmiss-20", "benign-extra-18",
]


def test_http_subset_status_matches_label(client, corpus):
    assert len(HTTP_SUBSET) == 20
    labels = {corpus[i]["label"] for i in HTTP_SUBSET}
    assert labels == {"attack", "benign"}
    for rid in HTTP_SUBSET:
        rec = corpus[rid]
        assert rec.get("phase", "call") == "call"
        body = {"tool": {"name": rec["tool"]}, "arguments": run.materialise(rec)}
        if rec.get("agent"):
            body["agent"] = {"id": rec["agent"]}
        resp = client.post("/api/check", json=body)
        if rec["label"] == "attack":
            assert resp.status_code == 403, (rid, resp.json())
            assert set(rec["expected_rules"]) & set(resp.json()["matched_detectors"]), rid
        else:
            assert resp.status_code == 200, (rid, resp.json())
