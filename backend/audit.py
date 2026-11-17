"""A persistent, tamper-evident audit log of decisions and approvals.

Every row is one event: a policy decision returned by ``/api/check`` or a
change to an approval. Rows are chained. Each carries the hash of the row
before it in the same chain, so removing, reordering or editing a row is
found by ``verify()``.

    hash = sha256(chain_id, seq, at_us, tenant, kind, payload_json, prev_hash)

Design choices, and what each costs:

* **One chain per writer process**, not one global chain. A global chain makes
  every replica wait for the same lock on every decision. With a chain per
  process, replicas never wait for each other. The cost: the log has no single
  total order (rows carry a timestamp), and deleting a whole chain, or the
  newest rows of one, is not detectable from the chain alone. Exporting the
  chain heads elsewhere closes that; this module does not do it.
* **Group commit.** Writes that arrive while an insert is in flight go out
  together in the next one. A caller still waits until its own row is stored.
* **No arguments.** A row holds the hash of the arguments, never their values,
  so the audit log does not become a second copy of every secret an agent
  touched.
* **Append only in the database too.** The Postgres table has a trigger that
  refuses UPDATE and DELETE. A database superuser can remove the trigger; the
  hash chain is what shows that something changed afterwards.

``MemoryAuditLog`` keeps rows in a list (tests, and the default when no
database is configured: nothing is persisted). ``PostgresAuditLog`` is the
persistent one.

Check a database from the command line::

    python -m backend.audit verify --dsn postgresql://...
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import secrets
import socket
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterable

logger = logging.getLogger(__name__)

GENESIS = "0" * 64
MAX_BATCH = 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS guardian_audit (
    chain_id     text   NOT NULL,
    seq          bigint NOT NULL,
    at_us        bigint NOT NULL,
    tenant       text   NOT NULL,
    kind         text   NOT NULL,
    payload_json text   NOT NULL,
    payload      jsonb  NOT NULL,
    prev_hash    text   NOT NULL,
    hash         text   NOT NULL,
    PRIMARY KEY (chain_id, seq)
);
CREATE INDEX IF NOT EXISTS guardian_audit_tenant_at ON guardian_audit (tenant, at_us);
CREATE OR REPLACE FUNCTION guardian_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'guardian_audit is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS guardian_audit_no_change ON guardian_audit;
CREATE TRIGGER guardian_audit_no_change BEFORE UPDATE OR DELETE ON guardian_audit
    FOR EACH ROW EXECUTE FUNCTION guardian_audit_append_only();
"""
# Two replicas starting together must not both run the DDL.
SCHEMA_LOCK = 7_203_114_001


class AuditError(Exception):
    """The audit row could not be stored."""


@dataclass(frozen=True)
class AuditRow:
    chain_id: str
    seq: int
    at_us: int
    tenant: str
    kind: str
    payload_json: str
    prev_hash: str
    hash: str

    @property
    def payload(self) -> dict:
        return json.loads(self.payload_json)


def canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def row_hash(chain_id: str, seq: int, at_us: int, tenant: str, kind: str, payload_json: str, prev_hash: str) -> str:
    body = json.dumps([chain_id, seq, at_us, tenant, kind, payload_json, prev_hash],
                      separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest()


def new_chain_id() -> str:
    """Names the process that wrote a chain: host (the pod name on Kubernetes) plus a nonce."""
    host = "".join(c if c.isalnum() or c in "-_." else "-" for c in socket.gethostname())[:48] or "host"
    return f"{host}-{secrets.token_hex(4)}"


def verify(rows: Iterable[AuditRow]) -> list[str]:
    """Problems found in the rows (empty: every chain is intact).

    Rows may come in any order and from several chains.
    """
    problems: list[str] = []
    chains: dict[str, list[AuditRow]] = {}
    for row in rows:
        chains.setdefault(row.chain_id, []).append(row)
    for chain_id, chain in sorted(chains.items()):
        chain.sort(key=lambda r: r.seq)
        prev = GENESIS
        expected = 1
        for row in chain:
            if row.seq != expected:
                problems.append(f"{chain_id}: expected seq {expected}, found {row.seq} (a row is missing or repeated)")
                expected = row.seq
            if row.prev_hash != prev:
                problems.append(f"{chain_id} seq {row.seq}: prev_hash does not match the row before it")
            want = row_hash(row.chain_id, row.seq, row.at_us, row.tenant, row.kind, row.payload_json, row.prev_hash)
            if row.hash != want:
                problems.append(f"{chain_id} seq {row.seq}: the row does not match its hash (it was edited)")
            prev = row.hash
            expected += 1
    return problems


class AuditLog(ABC):
    """Append-only log. ``write`` returns once the row is stored."""

    #: False for a log that keeps nothing across a restart.
    persistent = False

    def __init__(self, chain_id: str | None = None) -> None:
        self.chain_id = chain_id or new_chain_id()
        self._seq = 0
        self._prev = GENESIS
        self._pending: list[tuple[str, str, dict, asyncio.Future]] = []
        self._flusher: asyncio.Task | None = None

    @abstractmethod
    async def _store(self, rows: list[AuditRow]) -> None: ...

    async def write(self, kind: str, payload: dict, *, tenant: str = "") -> AuditRow:
        """Store one event. Raises AuditError if it could not be stored."""
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending.append((kind, tenant or "", payload, future))
        # The flush runs as its own task, so a caller that goes away (a client
        # that disconnects) cannot leave other callers' rows half written.
        if self._flusher is None or self._flusher.done():
            self._flusher = asyncio.create_task(self._flush())
        return await future

    async def _flush(self) -> None:
        # Whatever arrives while one insert is in flight goes out in the next.
        while self._pending:
            batch, self._pending = self._pending[:MAX_BATCH], self._pending[MAX_BATCH:]
            rows: list[AuditRow] = []
            seq, prev = self._seq, self._prev
            for kind, tenant, payload, _ in batch:
                seq += 1
                at_us = time.time_ns() // 1000
                text = canonical(payload)
                digest = row_hash(self.chain_id, seq, at_us, tenant, kind, text, prev)
                rows.append(AuditRow(self.chain_id, seq, at_us, tenant, kind, text, prev, digest))
                prev = digest
            try:
                await self._store(rows)
            except Exception as exc:
                # The chain position is not advanced: the next batch reuses these
                # sequence numbers, so a failed insert leaves no gap.
                error = AuditError(f"audit log unavailable: {type(exc).__name__}: {exc}")
                for *_, future in batch:
                    if not future.done():
                        future.set_exception(error)
                continue
            self._seq, self._prev = seq, prev
            for row, (*_, future) in zip(rows, batch):
                if not future.done():
                    future.set_result(row)

    async def ready(self) -> bool:
        """Whether a write would currently succeed."""
        return True

    async def close(self) -> None:
        if self._flusher is not None and not self._flusher.done():
            await self._flusher


class MemoryAuditLog(AuditLog):
    """Rows in a list. Nothing survives a restart."""

    def __init__(self, chain_id: str | None = None) -> None:
        super().__init__(chain_id)
        self.rows: list[AuditRow] = []

    async def _store(self, rows: list[AuditRow]) -> None:
        self.rows.extend(rows)


class PostgresAuditLog(AuditLog):
    """Rows in the ``guardian_audit`` table."""

    persistent = True

    def __init__(self, pool, chain_id: str | None = None) -> None:
        super().__init__(chain_id)
        self._pool = pool

    @classmethod
    async def create(cls, pool, chain_id: str | None = None) -> "PostgresAuditLog":
        async with pool.connection() as conn:
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(%s)", (SCHEMA_LOCK,))
                await conn.execute(SCHEMA)
        return cls(pool, chain_id)

    async def _store(self, rows: list[AuditRow]) -> None:
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.executemany(
                    "INSERT INTO guardian_audit (chain_id, seq, at_us, tenant, kind, payload_json, payload, "
                    "prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)",
                    [(r.chain_id, r.seq, r.at_us, r.tenant, r.kind, r.payload_json, r.payload_json,
                      r.prev_hash, r.hash) for r in rows],
                )

    async def ready(self) -> bool:
        try:
            async with self._pool.connection(timeout=2) as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            return False


async def read_rows(pool, *, tenant: str | None = None, chain_id: str | None = None) -> list[AuditRow]:
    where, params = [], []
    if tenant is not None:
        where.append("tenant = %s")
        params.append(tenant)
    if chain_id is not None:
        where.append("chain_id = %s")
        params.append(chain_id)
    sql = ("SELECT chain_id, seq, at_us, tenant, kind, payload_json, prev_hash, hash FROM guardian_audit"
           + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY chain_id, seq")
    async with pool.connection() as conn:
        cur = await conn.execute(sql, params)
        return [AuditRow(*row) for row in await cur.fetchall()]


async def verify_database(pool) -> list[str]:
    """Chain problems, plus rows whose queryable ``payload`` no longer matches the hashed text."""
    problems = verify(await read_rows(pool))
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT chain_id, seq FROM guardian_audit WHERE payload <> payload_json::jsonb ORDER BY chain_id, seq")
        for chain_id, seq in await cur.fetchall():
            problems.append(f"{chain_id} seq {seq}: the payload column differs from the hashed payload")
    return problems


def decision_payload(decision, call, *, session: str, principal: str | None, status_code: int,
                     arguments_sha256: str, approval_id: str = "", approval_status: str = "") -> dict:
    """What is kept about one decision. No argument values and no tool output."""
    out = {
        "decision_id": decision.decision_id,
        "phase": decision.phase,
        "effect": decision.effect,
        "enforced": decision.enforced,
        "blocked": decision.blocked,
        "mode": decision.mode,
        "rule_id": decision.rule_id,
        "policy_sha256": decision.policy_sha256,
        "matched_detectors": decision.matched_detectors,
        "tool": call.name,
        "server": call.server,
        "principal": principal or "",
        "claimed_agent": call.agent_id or call.agent_name or "",
        "session": session,
        "arguments_sha256": arguments_sha256,
        "status_code": status_code,
    }
    if approval_id:
        out["approval_id"] = approval_id
        out["approval_status"] = approval_status
    return out


def approval_payload(approval, change: str) -> dict:
    """What is kept about one approval change. The argument preview is left out."""
    return {
        "change": change,
        "approval_id": approval.id,
        "status": approval.status,
        "reason": approval.reason,
        "session": approval.session,
        "agent": approval.agent,
        "tool": approval.tool,
        "server": approval.server,
        "rule_id": approval.rule_id,
        "decision_id": approval.decision_id,
        "arguments_sha256": approval.arguments_sha256,
        "resolved_by": approval.resolved_by,
        "resolved_at": approval.resolved_at,
        "uses": approval.uses,
    }


async def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.audit", description="Check the audit log's hash chains.")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("verify", help="recompute every chain and report anything that does not match")
    check.add_argument("--dsn", default=os.environ.get("GUARDIAN_DATABASE_URL", ""),
                       help="Postgres connection string (default: GUARDIAN_DATABASE_URL)")
    args = parser.parse_args(argv)
    if not args.dsn:
        print("no database: pass --dsn or set GUARDIAN_DATABASE_URL", file=sys.stderr)
        return 2
    from psycopg_pool import AsyncConnectionPool

    async with AsyncConnectionPool(args.dsn, min_size=1, max_size=1, open=False) as pool:
        rows = await read_rows(pool)
        problems = await verify_database(pool)
    chains = len({r.chain_id for r in rows})
    if problems:
        for problem in problems:
            print("PROBLEM:", problem)
        print(f"{len(problems)} problem(s) in {len(rows)} rows across {chains} chain(s)")
        return 1
    print(f"OK: {len(rows)} rows across {chains} chain(s), every chain intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(sys.argv[1:])))
