"""Phase 4 through the HTTP API: tenant policies, the audit log, shared approvals, probes."""

from __future__ import annotations

import asyncio
import secrets

import pytest
from fastapi.testclient import TestClient

import server
from backend import audit
from tests.conftest import TEST_DATABASE_URL

BASE = """
version: 1
default_effect: deny
rules:
  - id: base-no-shell
    match: {tool: "shell.*"}
    effect: deny
  - id: base-read
    match: {tool: "fs.read"}
    effect: allow
"""
PAYMENTS = """
version: 1
rules:
  - id: payments-refund
    match: {tool: "payments.refund"}
    effect: require_approval
  - id: payments-lookup
    match: {tool: "payments.lookup"}
    effect: allow
"""
SEARCH = """
version: 1
rules:
  - id: search-web
    match: {tool: "web.search"}
    effect: allow
"""
KEYS = "payments.agent=payments-agent-key-0001,search.agent=search-agent-key-00001"
APPROVERS = "payments.alice=payments-alice-key-001,search.sam=search-sam-key-0000001"
PAY = {"Authorization": "Bearer payments-agent-key-0001"}
SEARCHER = {"Authorization": "Bearer search-agent-key-00001"}
ALICE = {"Authorization": "Bearer payments-alice-key-001"}
SAM = {"Authorization": "Bearer search-sam-key-0000001"}


@pytest.fixture
def tenants(tmp_path, monkeypatch, policy_file):
    policy_file(BASE)
    directory = tmp_path / "tenants"
    directory.mkdir()
    (directory / "payments.yaml").write_text(PAYMENTS)
    (directory / "search.yaml").write_text(SEARCH)
    monkeypatch.setattr(server.settings, "guardian_tenant_policies_dir", str(directory))
    monkeypatch.setattr(server.settings, "guardian_api_keys", KEYS)
    monkeypatch.setattr(server.settings, "guardian_approver_keys", APPROVERS)
    return directory


@pytest.fixture
def database(monkeypatch):
    """A fresh schema, and the server pointed at it."""
    if not TEST_DATABASE_URL:
        pytest.skip("GUARDIAN_TEST_DATABASE_URL is not set")
    import psycopg

    schema = "t_" + secrets.token_hex(6)
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in TEST_DATABASE_URL else "?"
    url = f"{TEST_DATABASE_URL}{sep}options=-csearch_path%3D{schema}"
    monkeypatch.setattr(server.settings, "guardian_database_url", url)
    yield url
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA "{schema}" CASCADE')


def _check(client, headers, tool, arguments=None):
    return client.post("/api/check", headers=headers, json={"tool": {"name": tool}, "arguments": arguments or {}})


def _rows(url):
    async def read():
        from psycopg_pool import AsyncConnectionPool

        async with AsyncConnectionPool(url, min_size=1, max_size=1, open=False) as pool:
            return await audit.read_rows(pool), await audit.verify_database(pool)

    return asyncio.run(read())


# ---- tenant policies ----


def test_each_tenant_gets_the_base_and_its_own_rules(client, tenants):
    assert _check(client, PAY, "payments.lookup").json()["rule_id"] == "payments-lookup"
    assert _check(client, PAY, "fs.read").json()["rule_id"] == "base-read"
    # Another tenant's rule does not apply, and what nothing matches is denied.
    other = _check(client, SEARCHER, "payments.lookup")
    assert other.status_code == 403 and other.json()["rule_id"] == "default"
    assert _check(client, SEARCHER, "web.search").status_code == 200
    assert _check(client, PAY, "web.search").status_code == 403


def test_a_base_deny_holds_for_every_tenant(client, tenants):
    (tenants / "payments.yaml").write_text(
        PAYMENTS + "  - {id: payments-shell, match: {tool: 'shell.*'}, effect: allow}\n")
    r = _check(client, PAY, "shell.exec", {"cmd": "ls"})
    assert r.status_code == 403 and r.json()["rule_id"] == "base-no-shell"


def test_the_tenant_comes_from_the_key_and_not_from_the_request(client, tenants):
    r = client.post("/api/check", headers=SEARCHER, json={
        "tool": {"name": "payments.lookup"}, "arguments": {},
        "agent": {"id": "payments.agent", "name": "payments.agent"}, "session_id": "app:payments.agent"})
    assert r.status_code == 403 and r.json()["rule_id"] == "default"


def test_the_policy_endpoint_shows_a_key_its_own_tenant(client, tenants):
    mine = client.get("/api/policy", headers=PAY).json()
    assert mine["tenant"] == "payments"
    assert [r["id"] for r in mine["rules"]] == ["base-no-shell", "base-read", "payments-refund", "payments-lookup"]
    theirs = client.get("/api/policy", headers=SAM).json()
    assert theirs["tenant"] == "search" and "payments-refund" not in [r["id"] for r in theirs["rules"]]
    assert mine["sha256"] != theirs["sha256"]


def test_a_tenant_file_that_breaks_refuses_that_tenant_and_no_other(client, tenants):
    (tenants / "ops.yaml").write_text("not: [valid")
    monkey_keys = KEYS + ",ops.agent=ops-agent-key-00000001"
    server.settings.guardian_api_keys = monkey_keys
    r = _check(client, {"Authorization": "Bearer ops-agent-key-00000001"}, "fs.read")
    assert r.status_code == 503 and r.json()["blocked"] is True
    assert _check(client, PAY, "fs.read").status_code == 200


def test_an_approver_answers_for_its_own_tenant_only(client, tenants):
    pending = _check(client, PAY, "payments.refund", {"amount": 40})
    assert pending.status_code == 202
    approval_id = pending.json()["approval_id"]
    # Another tenant's approver cannot see it, list it or answer it.
    assert client.get(f"/api/approvals/{approval_id}", headers=SAM).status_code == 404
    assert client.post(f"/api/approvals/{approval_id}", headers=SAM, json={"approve": True}).status_code == 404
    assert client.get("/api/approvals", headers=SAM,
                      params={"session": "app:payments.agent"}).json() == {"approvals": []}
    assert client.get(f"/api/approvals/{approval_id}", headers=PAY).json()["status"] == "pending"
    answered = client.post(f"/api/approvals/{approval_id}", headers=ALICE, json={"approve": True})
    assert answered.status_code == 200 and answered.json()["resolved_by"] == "payments.alice"
    assert _check(client, PAY, "payments.refund", {"amount": 40}).status_code == 200


# ---- probes ----


def test_probes_without_a_database(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok", "checks": {"policy": True}, "shared_state": False}


def test_readyz_checks_the_database(tenants, database):
    with TestClient(server.app) as client:
        ready = client.get("/readyz").json()
        assert ready == {"status": "ok", "checks": {"policy": True, "approvals": True, "audit": True},
                         "shared_state": True}


# ---- audit log ----


def test_every_decision_and_approval_change_is_in_the_audit_log(tenants, database):
    with TestClient(server.app) as client:
        assert _check(client, PAY, "payments.lookup", {"q": "token=sk-very-secret-value"}).status_code == 200
        assert _check(client, SEARCHER, "shell.exec", {"cmd": "rm -rf /"}).status_code == 403
        pending = _check(client, PAY, "payments.refund", {"amount": 40})
        approval_id = pending.json()["approval_id"]
        client.post(f"/api/approvals/{approval_id}", headers=ALICE, json={"approve": True})
        assert _check(client, PAY, "payments.refund", {"amount": 40}).status_code == 200
    rows, problems = _rows(database)
    assert problems == []
    decisions = [r for r in rows if r.kind == "decision"]
    assert [(r.tenant, r.payload["tool"], r.payload["effect"], r.payload["status_code"]) for r in decisions] == [
        ("payments", "payments.lookup", "allow", 200),
        ("search", "shell.exec", "deny", 403),
        ("payments", "payments.refund", "require_approval", 202),
        ("payments", "payments.refund", "allow", 200),
    ]
    assert decisions[0].payload["rule_id"] == "payments-lookup" and decisions[0].payload["principal"] == "payments.agent"
    assert decisions[2].payload["approval_id"] == approval_id and decisions[3].payload["approval_status"] == "approved"
    changes = [(r.tenant, r.payload["change"], r.payload["resolved_by"]) for r in rows if r.kind == "approval"]
    assert changes == [("payments", "pending", ""), ("payments", "approved", "payments.alice"),
                       ("payments", "used", "payments.alice")]
    # Hashes of the arguments, never the arguments.
    assert all("sk-very-secret-value" not in r.payload_json and "rm -rf" not in r.payload_json for r in rows)
    assert len({r.payload["arguments_sha256"] for r in decisions}) == 3


def test_a_decision_that_cannot_be_recorded_is_not_given(tenants, database, monkeypatch):
    with TestClient(server.app) as client:
        assert _check(client, PAY, "fs.read").status_code == 200

        async def down(rows):
            raise ConnectionError("database is down")

        monkeypatch.setattr(server.app.state.audit, "_store", down)
        refused = _check(client, PAY, "fs.read")
        assert refused.status_code == 503 and refused.json() == {
            "error": "Audit log unavailable; refusing to decide", "blocked": True}
        # The operator can choose availability over the record.
        monkeypatch.setattr(server.settings, "guardian_audit_required", False)
        assert _check(client, PAY, "fs.read").status_code == 200
    rows, problems = _rows(database)
    assert len(rows) == 1 and problems == []


def test_two_replicas_share_approvals_and_each_keeps_its_own_audit_chain(tenants, database):
    """Two app lifespans on one database stand in for two replicas."""
    with TestClient(server.app) as first:
        pending = _check(first, PAY, "payments.refund", {"amount": 40})
        approval_id = pending.json()["approval_id"]
    with TestClient(server.app) as second:  # a restart, or the other replica
        assert client_status(second, approval_id) == "pending"
        again = _check(second, PAY, "payments.refund", {"amount": 40})
        assert again.status_code == 202 and again.json()["approval_id"] == approval_id
        second.post(f"/api/approvals/{approval_id}", headers=ALICE, json={"approve": True})
        assert _check(second, PAY, "payments.refund", {"amount": 40}).status_code == 200
    rows, problems = _rows(database)
    assert problems == [] and len({r.chain_id for r in rows}) == 2


def client_status(client, approval_id):
    return client.get(f"/api/approvals/{approval_id}", headers=PAY).json()["status"]


def test_without_a_database_nothing_is_audited_and_approvals_are_in_memory(client, tenants):
    assert _check(client, PAY, "fs.read").status_code == 200
    assert server.app.state.audit is None
    assert type(server.app.state.approvals).__name__ == "InMemoryApprovalStore"
