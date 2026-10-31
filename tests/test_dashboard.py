"""The dashboard page: what it renders from hostile event data, and the
headers that back the escaping up.

The render tests run the real frontend/app.js in node against a small stub
DOM that records every innerHTML assignment, then parse that HTML here. They
skip when node is not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

import server

REPO = Path(__file__).resolve().parent.parent
APP_JS = REPO / "frontend" / "app.js"
INDEX = REPO / "frontend" / "index.html"

KEY_A = "a" * 24

# Each payload tries a different context: element content, a double-quoted
# attribute, a single-quoted attribute, and a bare class token.
HOSTILE = [
    '<img src=x onerror="alert(1)">',
    '"><svg onload=alert(2)>',
    "' onmouseover='alert(3)",
    'x onfocus=alert(4) autofocus',
]

# A stub DOM: enough of document/window for app.js to load and render.
# Every innerHTML assignment is recorded in HTML_OUT.
STUB = r"""
const HTML_OUT = [];
function el() {
  const e = {
    dataset: {}, style: {}, children: [], className: '', value: '__all', textContent: '', hidden: false,
    classList: { add() {}, remove() {} },
    set innerHTML(v) { HTML_OUT.push(String(v)); this._html = String(v); },
    get innerHTML() { return this._html || ''; },
    insertAdjacentHTML(_, v) { HTML_OUT.push(String(v)); },
    appendChild(c) { this.children.push(c); return c; },
    prepend(c) { this.children.unshift(c); },
    insertBefore(c) { this.children.unshift(c); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    addEventListener() {},
    remove() {},
    closest() { return null; },
    get offsetHeight() { return 400; },
  };
  return e;
}
const ELEMENTS = {};
globalThis.document = {
  getElementById(id) { return (ELEMENTS[id] ||= el()); },
  createElement() { return el(); },
  querySelector() { return null; },
  querySelectorAll() { return []; },
  head: el(),
};
globalThis.location = { pathname: '/', search: '', hash: '', protocol: 'http:', host: 'localhost' };
globalThis.history = { replaceState() {} };
const store = () => { const m = {}; return { getItem: k => m[k] ?? null, setItem: (k, v) => { m[k] = String(v); } }; };
globalThis.localStorage = store();
globalThis.sessionStorage = store();
globalThis.WebSocket = class { constructor() {} close() {} };
globalThis.fetch = () => Promise.reject(new Error('offline'));
globalThis.setInterval = () => 0;
globalThis.requestAnimationFrame = () => 0;
globalThis.CSS = { escape: s => String(s) };
"""


class _Collect(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str, str | None]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend((tag, k, v) for k, v in attrs)


def _render(calls: str) -> list[str]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    script = STUB + APP_JS.read_text(encoding="utf-8") + "\n" + calls + "\nprocess.stdout.write(JSON.stringify(HTML_OUT));"
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _assert_inert(html_chunks: list[str]) -> None:
    """No element or attribute the payloads could have introduced."""
    parser = _Collect()
    for chunk in html_chunks:
        parser.feed(chunk)
    parser.close()
    assert not {"img", "script", "iframe", "object"} & set(parser.tags), parser.tags
    assert "svg" not in parser.tags or all(
        k not in ("onload",) for t, k, _ in parser.attrs if t == "svg"), parser.attrs
    handlers = [(t, k, v) for t, k, v in parser.attrs if k.startswith("on")]
    assert not handlers, handlers
    assert not [a for a in parser.attrs if a[1] in ("autofocus", "src")], parser.attrs


@pytest.mark.parametrize("payload", HOSTILE)
def test_decision_card_escapes_every_field(payload):
    event = {
        "type": "decision", "agent": payload, "action": payload, "threat_level": payload,
        "tool_name": payload, "event_type": payload, "reason": payload, "rule_name": payload,
        "policy_rule_id": payload, "owasp_llm": payload, "owasp_agentic": payload, "effect": payload,
        "matched_detectors": [payload], "details": {"_source": payload, payload: payload},
        "decision_id": payload, "approval_id": payload,
    }
    blocked = {**event, "action": "blocked"}
    chunks = _render(f"handleEvent({json.dumps(event)}); handleEvent({json.dumps(blocked)});")
    assert len(chunks) >= 2
    _assert_inert(chunks)


@pytest.mark.parametrize("payload", HOSTILE)
def test_activity_approval_summary_and_targets_escape(payload):
    activity = [{"type": "agent_activity", "event_type": f"{t}_{payload}", "agent": payload, "task_id": payload,
                 "summary": payload, "data": {**d, "_source": payload}}
                for t, d in [("query", {"query": payload}), ("agent_start", {"agent": payload}),
                             ("evaluation", {"score": payload, "strengths": [payload], "tags": [payload]}),
                             ("status", {"message": payload}), ("output", {"content": payload, "complexity": payload}),
                             ("error", {"message": payload}), ("other", {})]]
    approval = {"type": "approval", "approval_id": payload, "status": payload, "uses": payload,
                "tool_name": payload, "agent": payload, "policy_rule_id": payload,
                "arguments": {payload: payload}, "diff_from": payload,
                "diff": [{"change": "added", "path": payload, "after": payload}],
                "resolved_by": payload, "note": payload, "reason": payload}
    resolved = {**approval, "status": "approved"}
    summary = {"type": "guardian_summary", "total_checked": payload, "total_flagged": payload,
               "by_rule": {payload: payload}, "by_severity": {payload: payload}}
    targets = [{"name": payload, "status": payload, "ws_url": payload}]
    calls = "".join(f"handleEvent({json.dumps(e)});" for e in [*activity, approval, resolved, summary])
    calls += f"updateAppsList({json.dumps(targets)});"
    calls += f"document.getElementById('connectStatus').innerHTML = renderVerifyError({json.dumps({'message': payload, 'code': payload})});"
    chunks = _render(calls)
    assert len(chunks) >= len(activity) + 3
    _assert_inert(chunks)


def test_escape_html_covers_attribute_quotes():
    out = _render("HTML_OUT.push(escapeHtml(`a\"b'c<d>&e`), escapeHtml(null), escapeHtml(42));")
    assert out[-3:] == ["a&quot;b&#39;c&lt;d&gt;&amp;e", "", "42"]


def test_token_in_the_fragment_is_kept_and_removed_from_the_url():
    calls = """
    HTML_OUT.push(AUTH_TOKEN, SESSION_ID);
    """
    stub_url = "globalThis.location = { pathname: '/', search: '?session=app:billing', hash: '#token=secret-key-123', protocol: 'http:', host: 'h' };\n" \
        "globalThis.history = { replaceState(_, __, url) { HTML_OUT.push('URL:' + url); } };\n"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    script = STUB + stub_url + APP_JS.read_text(encoding="utf-8") + calls + "\nprocess.stdout.write(JSON.stringify(HTML_OUT));"
    out = json.loads(subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60, check=True).stdout)
    assert "URL:/?session=app%3Abilling" in out
    assert "secret-key-123" in out and "app:billing" in out
    assert not [o for o in out if o.startswith("URL:") and "secret" in o]


class _Inline(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.handlers: list[tuple[str, str]] = []
        self.inline_scripts = 0
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        self.handlers += [(tag, k) for k, _ in attrs if k.startswith("on")]
        if tag == "script":
            self._in_script = not dict(attrs).get("src")

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_scripts += 1

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False


def test_page_has_no_inline_script_for_the_csp_to_block():
    parser = _Inline()
    parser.feed(INDEX.read_text(encoding="utf-8"))
    assert parser.handlers == [] and parser.inline_scripts == 0
    source = APP_JS.read_text(encoding="utf-8")
    assert "onclick=" not in source and "onchange=" not in source


def test_page_and_static_files_carry_a_strict_csp(client):
    for path in ("/", "/static/app.js", "/static/style.css"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        csp = resp.headers["content-security-policy"]
        directives = dict(d.strip().split(" ", 1) for d in csp.split(";"))
        assert directives["script-src"] == "'self'", csp
        assert directives["object-src"] == "'none'" and directives["frame-ancestors"] == "'none'"
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["referrer-policy"] == "no-referrer"
    # The API docs page loads its own CDN scripts; the policy is not applied there.
    assert "content-security-policy" not in client.get("/docs").headers


def test_stylesheet_and_script_urls_are_cache_busted():
    html = INDEX.read_text(encoding="utf-8")
    assert 'static/style.css?v=3' in html and 'static/app.js?v=5' in html


def test_card_shows_the_key_name_not_the_claimed_agent(client, monkeypatch):
    """With API keys, the agent on the dashboard card is the key's name. The
    body's agent is chosen by the caller and must not be shown as its identity."""
    monkeypatch.setattr(server.settings, "guardian_api_keys", f"billing={KEY_A}")
    with client.websocket_connect(f"/ws/events?session=app:billing&token={KEY_A}") as ws:
        resp = client.post("/api/check", json={
            "tool": {"name": "shell.exec"}, "arguments": {"cmd": "ls"},
            "agent": {"id": '<img src=x onerror=alert(1)>', "name": "ops"},
        }, headers={"Authorization": f"Bearer {KEY_A}"})
        assert resp.status_code == 403
        cards = []
        for _ in range(4):
            e = ws.receive_json()
            if e["type"] == "decision":
                cards.append(e)
                break
    assert cards and cards[0]["agent"] == "billing"


def test_card_without_keys_still_shows_the_reported_agent(client):
    with client.websocket_connect("/ws/events?session=s1") as ws:
        client.post("/api/check", json={"tool": {"name": "shell.exec"}, "arguments": {"cmd": "ls"},
                                        "agent": {"id": "researcher"}}, headers={"X-Session-Id": "s1"})
        card = next(e for e in (ws.receive_json() for _ in range(4)) if e["type"] == "decision")
    assert card["agent"] == "researcher"


def test_policy_endpoint_needs_a_key_when_keys_are_configured(client, monkeypatch):
    approver = "p" * 24
    monkeypatch.setattr(server.settings, "guardian_api_keys", f"billing={KEY_A}")
    monkeypatch.setattr(server.settings, "guardian_approver_keys", f"alice={approver}")
    assert client.get("/api/policy").status_code == 401
    assert client.get("/api/policy", headers={"Authorization": "Bearer " + "z" * 24}).status_code == 401
    for key in (KEY_A, approver):
        info = client.get("/api/policy", headers={"Authorization": f"Bearer {key}"})
        assert info.status_code == 200
        body = info.json()
        assert body["file"] == "default.yaml"
        assert "path" not in body and "reload_error" not in body
        assert str(REPO) not in info.text


def test_truncated_approval_offers_deny_only():
    """When the arguments were cut for display, the dashboard cannot show the
    whole call, so it must not offer Approve."""
    base = {"type": "approval", "approval_id": "ap1", "status": "pending", "uses": 0,
            "tool_name": "cloud.deploy", "agent": "a", "policy_rule_id": "r",
            "arguments": {"x": "1"}, "diff": []}
    full = "".join(_render(f"handleEvent({json.dumps(base)});"))
    cut = "".join(_render(f"handleEvent({json.dumps({**base, 'preview_truncated': True})});"))
    assert "btn-approve" in full and "btn-deny" in full
    assert "btn-approve" not in cut and "btn-deny" in cut
    assert "too large to show in full" in cut
