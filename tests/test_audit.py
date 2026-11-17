"""Phase 4: the persistent, hash-chained audit log."""

from __future__ import annotations

import asyncio
import dataclasses

import pytest

from backend import audit
from backend.audit import AuditError, MemoryAuditLog, PostgresAuditLog, read_rows, verify, verify_database

pytestmark = pytest.mark.asyncio


async def test_rows_are_chained_and_verify_clean():
    log = MemoryAuditLog("chain-a")
    for i in range(5):
        row = await log.write("decision", {"n": i}, tenant="payments")
        assert row.seq == i + 1
    assert log.rows[0].prev_hash == audit.GENESIS
    assert [r.prev_hash for r in log.rows[1:]] == [r.hash for r in log.rows[:-1]]
    assert verify(log.rows) == []


async def test_writes_arriving_together_all_land_in_order_with_no_gap():
    log = MemoryAuditLog("chain-a")
    rows = await asyncio.gather(*(log.write("decision", {"n": i}) for i in range(200)))
    assert sorted(r.seq for r in rows) == list(range(1, 201))
    assert [r.payload["n"] for r in log.rows] == list(range(200))
    assert verify(log.rows) == []


@pytest.mark.parametrize("tamper,problem", [
    (lambda rows: rows.pop(2), "a row is missing"),
    (lambda rows: rows.__setitem__(2, dataclasses.replace(rows[2], payload_json='{"n":99}')), "it was edited"),
    (lambda rows: rows.__setitem__(2, dataclasses.replace(rows[2], tenant="other")), "it was edited"),
    (lambda rows: rows.__setitem__(3, dataclasses.replace(rows[3], prev_hash="f" * 64)), "prev_hash does not match"),
])
async def test_removing_or_editing_a_row_is_found(tamper, problem):
    log = MemoryAuditLog("chain-a")
    for i in range(5):
        await log.write("decision", {"n": i})
    rows = list(log.rows)
    tamper(rows)
    assert any(problem in p for p in verify(rows))


async def test_chains_from_two_writers_are_checked_separately():
    a, b = MemoryAuditLog("chain-a"), MemoryAuditLog("chain-b")
    for i in range(3):
        await a.write("decision", {"n": i})
        await b.write("decision", {"n": i})
    assert verify(a.rows + b.rows) == []
    assert any("chain-b" in p for p in verify(a.rows + b.rows[1:]))


async def test_a_failed_store_raises_and_leaves_no_gap():
    class Flaky(MemoryAuditLog):
        fail = True

        async def _store(self, rows):
            if self.fail:
                raise ConnectionError("database is down")
            await super()._store(rows)

    log = Flaky("chain-a")
    with pytest.raises(AuditError, match="audit log unavailable"):
        await log.write("decision", {"n": 0})
    log.fail = False
    row = await log.write("decision", {"n": 1})
    assert row.seq == 1 and verify(log.rows) == []


async def test_the_payload_keeps_a_hash_of_the_arguments_and_never_their_values():
    from backend.guardian.schema import ToolCall
    from backend.policy import evaluate
    from backend.policy.loader import PolicyStore

    call = ToolCall(name="http.fetch", arguments={"url": "https://example.com/?token=sk-secret-value"})
    decision = evaluate(PolicyStore().get(), call, principal="payments.agent")
    payload = audit.decision_payload(decision, call, session="app:payments.agent", principal="payments.agent",
                                     status_code=403, arguments_sha256="ab" * 32)
    assert "sk-secret-value" not in audit.canonical(payload)
    assert payload["arguments_sha256"] == "ab" * 32 and payload["principal"] == "payments.agent"
    assert payload["policy_sha256"] == decision.policy_sha256 and payload["rule_id"] == decision.rule_id


# ---- Postgres ----


async def test_postgres_rows_survive_and_verify(pg_pool):
    log = await PostgresAuditLog.create(pg_pool, "chain-a")
    await asyncio.gather(*(log.write("decision", {"n": i}, tenant="payments") for i in range(50)))
    await log.write("approval", {"change": "approved"}, tenant="search")
    rows = await read_rows(pg_pool)
    assert len(rows) == 51 and await verify_database(pg_pool) == []
    assert len(await read_rows(pg_pool, tenant="search")) == 1
    # A second process gets its own chain and both stay valid.
    other = await PostgresAuditLog.create(pg_pool, "chain-b")
    await other.write("decision", {"n": 0})
    assert {r.chain_id for r in await read_rows(pg_pool)} == {"chain-a", "chain-b"}
    assert await verify_database(pg_pool) == []


async def test_postgres_refuses_update_and_delete(pg_pool):
    import psycopg

    log = await PostgresAuditLog.create(pg_pool, "chain-a")
    await log.write("decision", {"n": 0})
    for sql in ("UPDATE guardian_audit SET tenant = 'x'", "DELETE FROM guardian_audit"):
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            async with pg_pool.connection() as conn:
                await conn.execute(sql)
    assert len(await read_rows(pg_pool)) == 1


async def test_postgres_tampering_behind_the_trigger_is_found(pg_pool):
    """Someone with enough rights drops the trigger and edits a row: verify still catches it."""
    log = await PostgresAuditLog.create(pg_pool, "chain-a")
    for i in range(4):
        await log.write("decision", {"effect": "deny", "n": i})
    async with pg_pool.connection() as conn:
        await conn.execute("DROP TRIGGER guardian_audit_no_change ON guardian_audit")
        await conn.execute("UPDATE guardian_audit SET payload_json = replace(payload_json, 'deny', 'allow'), "
                           "payload = jsonb_set(payload, '{effect}', '\"allow\"') WHERE seq = 2")
    assert any("seq 2" in p and "edited" in p for p in await verify_database(pg_pool))
    async with pg_pool.connection() as conn:
        await conn.execute("DELETE FROM guardian_audit WHERE seq = 3")
    assert any("a row is missing" in p for p in await verify_database(pg_pool))


async def test_postgres_payload_column_edit_alone_is_found(pg_pool):
    log = await PostgresAuditLog.create(pg_pool, "chain-a")
    await log.write("decision", {"effect": "deny"})
    async with pg_pool.connection() as conn:
        await conn.execute("DROP TRIGGER guardian_audit_no_change ON guardian_audit")
        await conn.execute("UPDATE guardian_audit SET payload = '{\"effect\": \"allow\"}'::jsonb")
    assert any("payload column differs" in p for p in await verify_database(pg_pool))


async def test_postgres_down_raises_audit_error():
    from psycopg_pool import AsyncConnectionPool

    pool = AsyncConnectionPool("postgresql://nobody@127.0.0.1:1/none", min_size=0, max_size=1, open=False,
                               timeout=0.5, reconnect_timeout=0.5)
    await pool.open(wait=False)
    try:
        log = PostgresAuditLog(pool, "chain-a")
        with pytest.raises(AuditError):
            await log.write("decision", {"n": 0})
        assert await log.ready() is False
    finally:
        await pool.close()
