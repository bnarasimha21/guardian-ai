"""Approvals in Postgres, so several replicas share them and a restart keeps them.

``InMemoryApprovalStore`` holds the rules: what counts as the same call, when
a grant is usable, the deny cooldown, the per-session limit, the diff against
the previous approval. This store does not restate any of them. Each
operation:

1. takes a Postgres advisory lock on the session, so two replicas handling the
   same session take turns;
2. loads that session's approvals into a scratch ``InMemoryApprovalStore``;
3. runs the operation there, with the same code a single process runs;
4. writes back the rows that changed, in the same transaction.

What that buys and what it costs:

* The behaviour is the in-memory store's by construction, including the
  guarantee that two identical calls arriving together, on different
  replicas, open one approval and that a single-use grant lets one through.
* Every operation is a round trip to the database and reads the whole
  session (at most ``max_pending_per_session`` pending rows plus what the
  retention window keeps). Sessions are independent, so load on one tenant
  does not make another wait.
* Timeouts are applied when an approval is next read, and by a sweep on each
  replica, not by a timer. A timed-out approval may sit as "pending" in the
  table for up to ``sweep_seconds`` if nobody asks about it; nobody can use it
  in that time, because every read applies the timeout first.
* ``wait()`` polls. Another replica's answer is seen within ``poll_seconds``.
* Listeners (the dashboard, telemetry) run on the replica that made the
  change. A dashboard connected to another replica does not get the event
  live. The audit log gets every change, whichever replica made it.
* Replicas compare ``time.time()``. Their clocks need to agree to within a
  second or so, which Kubernetes nodes do.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time
from typing import Any, Awaitable, Callable

from .store import (
    MAX_APPROVALS, MAX_PENDING_PER_SESSION, PENDING, RETAIN_SECONDS, ApprovalStore, InMemoryApprovalStore,
    PendingApproval, _SURROGATE,
)

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS guardian_approvals (
    id          text PRIMARY KEY,
    session     text NOT NULL,
    status      text NOT NULL,
    created_at  double precision NOT NULL,
    expires_at  double precision NOT NULL,
    resolved_at double precision,
    data        jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS guardian_approvals_session ON guardian_approvals (session);
CREATE INDEX IF NOT EXISTS guardian_approvals_due ON guardian_approvals (expires_at) WHERE status = 'pending';
"""
SCHEMA_LOCK = 7_203_114_002
SESSION_LOCK_CLASS = 72031


def _clean(value: Any) -> Any:
    """jsonb refuses lone surrogates and NUL; both become U+FFFD."""
    if isinstance(value, str):
        return _SURROGATE.sub("�", value).replace("\x00", "�")
    if isinstance(value, dict):
        return {_clean(str(k)): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, float) and value != value:  # NaN
        return "nan"
    if isinstance(value, float) and value in (float("inf"), float("-inf")):
        return str(value)
    return value


def to_json(approval: PendingApproval) -> str:
    return json.dumps(_clean(dataclasses.asdict(approval)), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def from_json(data: dict) -> PendingApproval:
    fields = {f.name for f in dataclasses.fields(PendingApproval)}
    data = {k: v for k, v in data.items() if k in fields}
    # JSON has no tuples; the diff code indexes these as (label, hash, shown).
    data["arguments_fingerprint"] = {k: tuple(v) for k, v in (data.get("arguments_fingerprint") or {}).items()}
    return PendingApproval(**data)


class _Scratch(InMemoryApprovalStore):
    """The in-memory store, loaded with one session and without timers."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.changes: list[tuple[PendingApproval, str]] = []
        self.add_listener(self._remember)

    async def _remember(self, approval: PendingApproval, change: str) -> None:
        self.changes.append((approval, change))

    def _arm_timer(self, approval: PendingApproval) -> None:
        return None  # timeouts are applied on read; see the module docstring

    def load(self, approvals: list[PendingApproval]) -> None:
        for approval in approvals:
            self._items[approval.id] = approval
            event = asyncio.Event()
            if approval.status != PENDING:
                event.set()
            self._events[approval.id] = event


class PostgresApprovalStore(ApprovalStore):
    def __init__(self, pool, *, max_approvals: int = MAX_APPROVALS,
                 max_pending_per_session: int = MAX_PENDING_PER_SESSION,
                 clock: Callable[[], float] = time.time, poll_seconds: float = 0.25,
                 sweep_seconds: float = 5.0) -> None:
        super().__init__()
        self._pool = pool
        self.max_approvals = max_approvals
        self.max_pending_per_session = max_pending_per_session
        self._clock = clock
        self.poll_seconds = poll_seconds
        self.sweep_seconds = sweep_seconds
        self._sweeper: asyncio.Task | None = None

    @classmethod
    async def open(cls, pool, **kwargs) -> "PostgresApprovalStore":
        """Create the table if it is missing and return a store on ``pool``."""
        async with pool.connection() as conn:
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(%s)", (SCHEMA_LOCK,))
                await conn.execute(SCHEMA)
        return cls(pool, **kwargs)

    def start_sweeper(self) -> None:
        """Apply timeouts nobody is asking about, so they are recorded and shown."""
        if self._sweeper is None or self._sweeper.done():
            self._sweeper = asyncio.create_task(self._sweep_forever())

    async def _sweep_forever(self) -> None:
        while True:
            await asyncio.sleep(self.sweep_seconds)
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("approval sweep failed")

    async def sweep(self) -> int:
        """Time out every pending approval that is past its deadline. Returns how many sessions were touched."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                "SELECT DISTINCT session FROM guardian_approvals WHERE status = 'pending' AND expires_at <= %s",
                (self._clock(),))
            sessions = [row[0] for row in await cur.fetchall()]
        for session in sessions:
            await self._in_session(session, lambda scratch: scratch.list(session=session))
        # Old resolved rows of sessions that never come back.
        async with self._pool.connection() as conn:
            await conn.execute(
                "DELETE FROM guardian_approvals WHERE status <> 'pending' AND "
                "coalesce(resolved_at, created_at) + (data->>'grant_ttl_seconds')::float8 "
                "+ (data->>'timeout_seconds')::float8 + %s < %s", (RETAIN_SECONDS, self._clock()))
        return len(sessions)

    # -- the one way in ------------------------------------------------------

    async def _in_session(self, session: str, operation: Callable[[_Scratch], Awaitable[Any]]) -> Any:
        async with self._pool.connection() as conn:
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))", (SESSION_LOCK_CLASS, session))
                cur = await conn.execute("SELECT id, data FROM guardian_approvals WHERE session = %s", (session,))
                loaded = {aid: data for aid, data in await cur.fetchall()}
                cur = await conn.execute("SELECT count(*) FROM guardian_approvals WHERE session <> %s", (session,))
                elsewhere = (await cur.fetchone())[0]
                scratch = _Scratch(
                    # The limit is for the whole table; this session may use what the others leave.
                    max_approvals=max(0, self.max_approvals - elsewhere),
                    max_pending_per_session=self.max_pending_per_session, clock=self._clock,
                )
                approvals = [from_json(data) for data in loaded.values()]
                scratch.load(approvals)
                before = {a.id: to_json(a) for a in approvals}
                # An exception here (not pending, unknown id, over capacity) rolls
                # the transaction back; nothing the operation did is kept.
                result = await operation(scratch)
                for aid, approval in scratch._items.items():
                    text = to_json(approval)
                    if before.get(aid) == text:
                        continue
                    await conn.execute(
                        "INSERT INTO guardian_approvals (id, session, status, created_at, expires_at, resolved_at, "
                        "data) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb) ON CONFLICT (id) DO UPDATE SET "
                        "status = EXCLUDED.status, resolved_at = EXCLUDED.resolved_at, data = EXCLUDED.data",
                        (aid, approval.session, approval.status, approval.created_at, approval.expires_at,
                         approval.resolved_at, text))
                gone = [aid for aid in before if aid not in scratch._items]
                if gone:
                    await conn.execute("DELETE FROM guardian_approvals WHERE id = ANY(%s)", (gone,))
        # After the commit: a listener must never see a change that was rolled back.
        for approval, change in scratch.changes:
            await self._notify(approval, change)
        return result

    async def _session_of(self, approval_id: str) -> str | None:
        async with self._pool.connection() as conn:
            cur = await conn.execute("SELECT session FROM guardian_approvals WHERE id = %s", (approval_id,))
            row = await cur.fetchone()
        return row[0] if row else None

    # -- interface -----------------------------------------------------------

    async def create(self, *, session, agent, tool, server, arguments, decision,
                     timeout_seconds, grant_ttl_seconds) -> PendingApproval:
        return await self._in_session(session, lambda s: s.create(
            session=session, agent=agent, tool=tool, server=server, arguments=arguments, decision=decision,
            timeout_seconds=timeout_seconds, grant_ttl_seconds=grant_ttl_seconds))

    async def find_or_create(self, *, session, agent, tool, server, arguments, decision,
                             timeout_seconds, grant_ttl_seconds, deny_cooldown_seconds=0):
        return await self._in_session(session, lambda s: s.find_or_create(
            session=session, agent=agent, tool=tool, server=server, arguments=arguments, decision=decision,
            timeout_seconds=timeout_seconds, grant_ttl_seconds=grant_ttl_seconds,
            deny_cooldown_seconds=deny_cooldown_seconds))

    async def get(self, approval_id: str) -> PendingApproval | None:
        session = await self._session_of(approval_id)
        if session is None:
            return None
        return await self._in_session(session, lambda s: s.get(approval_id))

    async def resolve(self, approval_id, *, approve, by, note="", reason=""):
        session = await self._session_of(approval_id)
        if session is None:
            raise KeyError(approval_id)
        return await self._in_session(session, lambda s: s.resolve(
            approval_id, approve=approve, by=by, note=note, reason=reason))

    async def wait(self, approval_id, timeout):
        approval = await self.get(approval_id)
        deadline = time.monotonic() + max(0.0, timeout)
        while approval is not None and approval.status == PENDING:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            await asyncio.sleep(min(self.poll_seconds, left))
            approval = await self.get(approval_id)
        return approval

    async def find(self, *, session, agent, sha256):
        return await self._in_session(session, lambda s: s.find(session=session, agent=agent, sha256=sha256))

    async def use(self, approval_id):
        session = await self._session_of(approval_id)
        if session is None:
            return False
        return await self._in_session(session, lambda s: s.use(approval_id))

    async def list(self, *, session, status=None):
        return await self._in_session(session, lambda s: s.list(session=session, status=status))

    async def ready(self) -> bool:
        try:
            async with self._pool.connection(timeout=2) as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self._sweeper is not None:
            self._sweeper.cancel()
            try:
                await self._sweeper
            except (asyncio.CancelledError, Exception):
                pass
            self._sweeper = None
