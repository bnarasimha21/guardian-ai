"""Phase 4: approvals shared by several replicas through Postgres.

Two ``PostgresApprovalStore`` objects on the same database stand in for two
replicas of the server.
"""

from __future__ import annotations

import asyncio

import pytest

from backend.approvals import APPROVED, DENIED, PENDING, ApprovalCapacityError, ApprovalNotPending
from backend.approvals.postgres import PostgresApprovalStore, from_json, to_json

pytestmark = pytest.mark.asyncio

CALL = dict(session="app:payments.agent", agent="payments.agent", tool="payments.refund", server=None,
            arguments={"amount": 40, "to": "acct-1"}, decision={"rule_id": "refund", "decision_id": "d1"},
            timeout_seconds=60, grant_ttl_seconds=0)


async def _replicas(pool, n=2, **kwargs):
    return [await PostgresApprovalStore.open(pool, **kwargs) for _ in range(n)]


async def test_an_approval_opened_on_one_replica_is_answered_on_another(pg_pool):
    a, b = await _replicas(pg_pool)
    status, approval = await a.find_or_create(**CALL)
    assert status == "created" and approval.status == PENDING
    assert (await b.get(approval.id)).status == PENDING
    resolved = await b.resolve(approval.id, approve=True, by="alice")
    assert resolved.status == APPROVED and (await a.get(approval.id)).resolved_by == "alice"
    # The grant is single use, whichever replica the retries reach.
    assert (await a.find_or_create(**CALL))[0] == "granted"
    assert (await b.find_or_create(**CALL))[0] == "created"


async def test_identical_calls_arriving_on_different_replicas_open_one_approval(pg_pool):
    replicas = await _replicas(pg_pool, 4)
    outcomes = await asyncio.gather(*(r.find_or_create(**CALL) for r in replicas for _ in range(5)))
    assert sorted(status for status, _ in outcomes) == ["created"] + ["waiting"] * 19
    assert len({approval.id for _, approval in outcomes}) == 1


async def test_a_single_use_grant_lets_exactly_one_racing_call_through(pg_pool):
    replicas = await _replicas(pg_pool, 4)
    _, approval = await replicas[0].find_or_create(**CALL)
    await replicas[1].resolve(approval.id, approve=True, by="alice")
    outcomes = await asyncio.gather(*(r.find_or_create(**CALL) for r in replicas for _ in range(5)))
    statuses = sorted(status for status, _ in outcomes)
    assert statuses.count("granted") == 1 and statuses.count("created") == 1
    assert statuses.count("waiting") == 18


async def test_approvals_survive_a_restart(pg_pool):
    (a,) = await _replicas(pg_pool, 1)
    _, approval = await a.find_or_create(**CALL)
    await a.close()
    (restarted,) = await _replicas(pg_pool, 1)
    assert (await restarted.get(approval.id)).status == PENDING
    assert [x.id for x in await restarted.list(session=CALL["session"])] == [approval.id]


async def test_wait_sees_an_answer_given_on_another_replica(pg_pool):
    a, b = await _replicas(pg_pool, poll_seconds=0.05)
    _, approval = await a.find_or_create(**CALL)

    async def answer():
        await asyncio.sleep(0.2)
        await b.resolve(approval.id, approve=False, by="bob", note="no")

    waited, _ = await asyncio.gather(a.wait(approval.id, 5), answer())
    assert waited.status == DENIED and waited.resolved_by == "bob"
    assert (await a.wait("apr_missing", 0.1)) is None


async def test_no_answer_times_out_as_denied_on_read_and_by_the_sweep(pg_pool):
    now = [1000.0]
    a, b = await _replicas(pg_pool, clock=lambda: now[0])
    _, first = await a.find_or_create(**{**CALL, "timeout_seconds": 10})
    _, second = await a.find_or_create(**{**CALL, "session": "app:search.agent", "timeout_seconds": 10})
    now[0] += 11
    seen = await b.get(first.id)
    assert seen.status == DENIED and seen.reason == "timeout"
    # Nobody asks about the second one: the sweep applies its timeout.
    events = []

    async def listener(approval, change):
        events.append((approval.id, change))

    b.add_listener(listener)
    assert await b.sweep() == 1
    assert events == [(second.id, DENIED)]
    with pytest.raises(ApprovalNotPending):
        await a.resolve(second.id, approve=True, by="late")


async def test_an_approval_arriving_after_the_deadline_is_a_timeout(pg_pool):
    now = [1000.0]
    a, b = await _replicas(pg_pool, clock=lambda: now[0])
    _, approval = await a.find_or_create(**{**CALL, "timeout_seconds": 10})
    now[0] += 11
    # As in the single-process store: a yes that arrives too late is recorded as the timeout.
    late = await b.resolve(approval.id, approve=True, by="alice")
    assert late.status == DENIED and late.reason == "timeout" and late.resolved_by == "guardian"
    assert (await a.get(approval.id)).reason == "timeout"
    assert (await a.find_or_create(**{**CALL, "timeout_seconds": 10}))[0] == "created"


async def test_the_deny_cooldown_holds_across_replicas(pg_pool):
    now = [1000.0]
    a, b = await _replicas(pg_pool, clock=lambda: now[0])
    call = {**CALL, "deny_cooldown_seconds": 30}
    _, approval = await a.find_or_create(**call)
    await b.resolve(approval.id, approve=False, by="bob")
    assert (await b.find_or_create(**call))[0] == "denied_recently"
    assert (await a.find_or_create(**call))[0] == "denied_recently"
    now[0] += 31
    assert (await a.find_or_create(**call))[0] == "created"


async def test_a_changed_argument_needs_its_own_approval_and_shows_the_diff(pg_pool):
    a, b = await _replicas(pg_pool)
    _, first = await a.find_or_create(**CALL)
    await a.resolve(first.id, approve=True, by="alice")
    status, second = await b.find_or_create(**{**CALL, "arguments": {"amount": 4000, "to": "acct-1"}})
    assert status == "created" and second.diff_from == first.id
    assert second.diff == [{"path": "amount", "change": "changed", "before": 40, "after": 4000}]


async def test_sessions_and_agents_do_not_share_grants(pg_pool):
    a, b = await _replicas(pg_pool)
    _, approval = await a.find_or_create(**CALL)
    await a.resolve(approval.id, approve=True, by="alice")
    assert (await b.find_or_create(**{**CALL, "agent": "payments.other"}))[0] == "created"
    assert (await b.find_or_create(**{**CALL, "session": "app:search.agent"}))[0] == "created"
    assert (await b.find(session=CALL["session"], agent=CALL["agent"],
                         sha256=approval.arguments_sha256)).id == approval.id
    assert await b.list(session="app:nobody") == []


async def test_the_per_session_and_whole_table_limits_hold_across_replicas(pg_pool):
    a, b = await _replicas(pg_pool, max_pending_per_session=2, max_approvals=3)
    for i in range(2):
        await (a if i else b).find_or_create(**{**CALL, "arguments": {"n": i}})
    with pytest.raises(ApprovalCapacityError, match="already has 2 approvals waiting"):
        await b.find_or_create(**{**CALL, "arguments": {"n": 2}})
    await a.find_or_create(**{**CALL, "session": "app:search.agent"})
    with pytest.raises(ApprovalCapacityError, match="Too many approvals"):
        await b.find_or_create(**{**CALL, "session": "app:ops.agent"})


async def test_a_refused_operation_changes_nothing(pg_pool):
    (a,) = await _replicas(pg_pool, 1)
    _, approval = await a.find_or_create(**CALL)
    await a.resolve(approval.id, approve=False, by="bob")
    with pytest.raises(ApprovalNotPending):
        await a.resolve(approval.id, approve=True, by="alice")
    with pytest.raises(KeyError):
        await a.resolve("apr_missing", approve=True, by="alice")
    assert (await a.get(approval.id)).resolved_by == "bob" and await a.use(approval.id) is False
    assert await a.use("apr_missing") is False


async def test_listeners_run_after_the_commit_on_the_replica_that_made_the_change(pg_pool):
    a, b = await _replicas(pg_pool)
    seen_a, seen_b = [], []

    async def on_a(approval, change):
        # The row is already visible to another replica when the listener runs.
        seen_a.append((change, (await b.get(approval.id)).status))

    async def on_b(approval, change):
        seen_b.append(change)

    a.add_listener(on_a)
    b.add_listener(on_b)
    _, approval = await a.find_or_create(**CALL)
    await a.resolve(approval.id, approve=True, by="alice")
    assert seen_a == [(PENDING, PENDING), (APPROVED, APPROVED)] and seen_b == []


async def test_awkward_arguments_survive_the_round_trip(pg_pool):
    a, b = await _replicas(pg_pool)
    arguments = {"text": "bad \ud800 surrogate and \x00 nul", "n": float("nan"), "big": 2 ** 60,
                 "nested": {"a.b": 1, "a": {"b": 2}}}
    _, approval = await a.find_or_create(**{**CALL, "arguments": arguments})
    again = await b.get(approval.id)
    assert again.arguments_sha256 == approval.arguments_sha256
    assert again.arguments_preview["big"] == str(2 ** 60)
    assert from_json(__import__("json").loads(to_json(again))) == again
    # The retry carries the same arguments and joins the same approval.
    assert (await b.find_or_create(**{**CALL, "arguments": arguments}))[0] == "waiting"


async def test_old_resolved_approvals_are_removed_by_the_sweep(pg_pool):
    now = [1000.0]
    (a,) = await _replicas(pg_pool, 1, clock=lambda: now[0])
    _, approval = await a.find_or_create(**CALL)
    await a.resolve(approval.id, approve=False, by="bob")
    now[0] += 3600 + 200
    await a.sweep()
    assert await a.get(approval.id) is None
