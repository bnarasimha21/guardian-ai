"""Pending human approvals for ``require_approval`` decisions.

An approval is bound to one exact call: ``sha256`` of the tool name, server and
canonical JSON arguments, plus the session and the caller. A call that differs
in any argument needs its own approval.

Lifecycle::

    pending --approve--> approved --(used once, or reused until grant TTL)--> spent
           \\--deny-----> denied
            \\--timeout--> denied (reason "timeout")   fail closed

``ApprovalStore`` is the interface; ``InMemoryApprovalStore`` keeps everything
in process memory (lost on restart, one process only). A SQLite or Redis
implementation can replace it behind the same methods.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"

MAX_APPROVALS = 10_000
MAX_PENDING_PER_SESSION = 100
# Resolved approvals are kept this long after they stop mattering, so a poller
# that comes back late still gets an answer, then pruned.
RETAIN_SECONDS = 3600
MAX_PREVIEW_PATHS = 200
MAX_PREVIEW_CHARS = 500
_SURROGATE = re.compile("[\ud800-\udfff]")


class ApprovalError(Exception):
    pass


class ApprovalNotPending(ApprovalError):
    """The approval was already resolved (or timed out)."""


class ApprovalCapacityError(ApprovalError):
    """Too many approvals held; the call is refused rather than queued."""


def arguments_sha256(tool: str, server: str | None, arguments: Any) -> str:
    """Hash of the exact call. Key order does not matter; any value change does."""
    canonical = json.dumps(
        {"tool": tool, "server": server, "arguments": arguments},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
    )
    # surrogatepass: a lone surrogate in an argument is still hashed (to its
    # own distinct bytes) instead of raising.
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def _display(value: Any) -> Any:
    """``value`` as something JSON can carry: NaN and infinities become text,
    lone surrogates become U+FFFD. The preview is for people, not the hash."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, str):
        return _SURROGATE.sub("\ufffd", value)
    return value


def flatten(value: Any, limit: int = MAX_PREVIEW_PATHS) -> dict[str, Any]:
    """{dotted.path: scalar} for display and diffing; long strings are cut."""
    out: dict[str, Any] = {}
    stack: list[tuple[str, Any]] = [("", value)]
    while stack and len(out) < limit:
        path, v = stack.pop()
        if isinstance(v, dict) and v:
            for k in reversed(list(v.keys())):
                stack.append((f"{path}.{k}" if path else str(k), v[k]))
        elif isinstance(v, list) and v:
            for i in range(len(v) - 1, -1, -1):
                stack.append((f"{path}.{i}" if path else str(i), v[i]))
        else:
            if isinstance(v, str) and len(v) > MAX_PREVIEW_CHARS:
                v = v[:MAX_PREVIEW_CHARS] + "..."
            elif not isinstance(v, (str, int, float, bool, type(None))):
                v = str(v)[:MAX_PREVIEW_CHARS]
            key = path or "$"
            if len(key) > MAX_PREVIEW_CHARS:
                key = key[:MAX_PREVIEW_CHARS] + "..."
            key = _display(key)
            # Cutting, U+FFFD and dotted keys ({"a.b": 1} vs {"a": {"b": 1}})
            # can give two arguments the same label. Neither may hide the other
            # from the approver, so a repeat gets a numbered suffix.
            if key in out:
                n = 2
                while f"{key} [{n}]" in out:
                    n += 1
                key = f"{key} [{n}]"
            out[key] = _display(v)
    return out


def diff(before: dict[str, Any], after: dict[str, Any]) -> list[dict]:
    """Changed, added and removed paths between two flattened argument sets."""
    changes = []
    for path in sorted(set(before) | set(after)):
        if path not in before:
            changes.append({"path": path, "change": "added", "after": after[path]})
        elif path not in after:
            changes.append({"path": path, "change": "removed", "before": before[path]})
        elif before[path] != after[path]:
            changes.append({"path": path, "change": "changed", "before": before[path], "after": after[path]})
    return changes


@dataclass
class PendingApproval:
    id: str
    session: str
    agent: str
    tool: str
    server: str | None
    arguments_sha256: str
    arguments_preview: dict[str, Any]
    decision: dict
    created_at: float
    expires_at: float
    timeout_seconds: float
    grant_ttl_seconds: float
    status: str = PENDING
    reason: str = ""
    note: str = ""
    resolved_by: str = ""
    resolved_at: float | None = None
    uses: int = 0
    diff_from: str = ""
    diff: list[dict] = field(default_factory=list)

    @property
    def rule_id(self) -> str:
        return str(self.decision.get("rule_id", ""))

    @property
    def decision_id(self) -> str:
        return str(self.decision.get("decision_id", ""))

    def grant_valid_until(self) -> float | None:
        """Until when this approval lets an identical call through (None = not at all)."""
        if self.status != APPROVED or self.resolved_at is None:
            return None
        if self.grant_ttl_seconds > 0:
            return self.resolved_at + self.grant_ttl_seconds
        # Single use: one identical call, which must arrive within the
        # approval timeout after the human said yes.
        if self.uses >= 1:
            return None
        return self.resolved_at + self.timeout_seconds

    def usable(self, now: float | None = None) -> bool:
        until = self.grant_valid_until()
        return until is not None and (now if now is not None else time.time()) < until

    def to_dict(self) -> dict:
        return {
            "approval_id": self.id,
            "status": self.status,
            "reason": self.reason,
            "note": self.note,
            "tool": self.tool,
            "server": self.server,
            "agent": self.agent,
            "rule_id": self.rule_id,
            "decision_id": self.decision_id,
            "arguments_sha256": self.arguments_sha256,
            "arguments": self.arguments_preview,
            "diff_from": self.diff_from,
            "diff": self.diff,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "grant_ttl_seconds": self.grant_ttl_seconds,
            "grant_valid_until": self.grant_valid_until(),
            "uses": self.uses,
        }


# change is one of: "pending", "approved", "denied", "used"
Listener = Callable[[PendingApproval, str], Awaitable[None]]


class ApprovalStore(ABC):
    """Interface for approval storage. All methods run on the event loop."""

    def __init__(self) -> None:
        self._listeners: list[Listener] = []

    def add_listener(self, listener: Listener) -> None:
        self._listeners.append(listener)

    async def _notify(self, approval: PendingApproval, change: str) -> None:
        for listener in list(self._listeners):
            try:
                await listener(approval, change)
            except Exception:  # a broken listener must not undo a decision
                import logging
                logging.getLogger(__name__).exception("approval listener failed")

    @abstractmethod
    async def create(self, *, session: str, agent: str, tool: str, server: str | None, arguments: Any,
                     decision: dict, timeout_seconds: float, grant_ttl_seconds: float) -> PendingApproval: ...

    @abstractmethod
    async def get(self, approval_id: str) -> PendingApproval | None: ...

    @abstractmethod
    async def resolve(self, approval_id: str, *, approve: bool, by: str, note: str = "",
                      reason: str = "") -> PendingApproval: ...

    @abstractmethod
    async def wait(self, approval_id: str, timeout: float) -> PendingApproval | None:
        """Return once the approval is no longer pending, or after ``timeout``."""

    @abstractmethod
    async def find(self, *, session: str, agent: str, sha256: str) -> PendingApproval | None:
        """A pending approval or a usable grant for exactly this call, if any."""

    @abstractmethod
    async def use(self, approval_id: str) -> bool:
        """Spend the grant for one call. False if it is no longer usable."""

    @abstractmethod
    async def list(self, *, session: str, status: str | None = None) -> list[PendingApproval]: ...

    async def close(self) -> None:
        """Cancel timers. Pending approvals stay pending."""


class InMemoryApprovalStore(ApprovalStore):
    def __init__(self, *, max_approvals: int = MAX_APPROVALS,
                 max_pending_per_session: int = MAX_PENDING_PER_SESSION,
                 clock: Callable[[], float] = time.time) -> None:
        super().__init__()
        self._items: dict[str, PendingApproval] = {}
        self._events: dict[str, asyncio.Event] = {}
        self._timers: dict[str, asyncio.TimerHandle] = {}
        self._lock = asyncio.Lock()
        self.max_approvals = max_approvals
        self.max_pending_per_session = max_pending_per_session
        self._clock = clock

    # -- internals -----------------------------------------------------------

    def _prune(self, now: float) -> None:
        stale = []
        for a in self._items.values():
            if a.status == PENDING:
                continue
            until = a.grant_valid_until() or a.resolved_at or a.created_at
            if now - until > RETAIN_SECONDS:
                stale.append(a.id)
        for aid in stale:
            self._drop(aid)
        if len(self._items) >= self.max_approvals:
            # Oldest resolved first; pending approvals are never dropped.
            resolved = sorted((a for a in self._items.values() if a.status != PENDING),
                              key=lambda a: a.resolved_at or a.created_at)
            for a in resolved[: len(self._items) - self.max_approvals + 1]:
                self._drop(a.id)

    def _drop(self, aid: str) -> None:
        self._items.pop(aid, None)
        self._events.pop(aid, None)
        timer = self._timers.pop(aid, None)
        if timer is not None:
            timer.cancel()

    def _arm_timer(self, approval: PendingApproval) -> None:
        loop = asyncio.get_running_loop()
        delay = max(0.0, approval.expires_at - self._clock())
        self._timers[approval.id] = loop.call_later(
            delay, lambda: asyncio.ensure_future(self._expire(approval.id)),
        )

    async def _expire(self, aid: str) -> None:
        try:
            await self.resolve(aid, approve=False, by="guardian", reason="timeout")
        except (ApprovalNotPending, KeyError):
            pass

    async def _expire_if_due(self, approval: PendingApproval) -> None:
        if approval.status == PENDING and self._clock() >= approval.expires_at:
            await self._expire(approval.id)

    # -- interface -----------------------------------------------------------

    async def create(self, *, session, agent, tool, server, arguments, decision,
                     timeout_seconds, grant_ttl_seconds) -> PendingApproval:
        now = self._clock()
        async with self._lock:
            self._prune(now)
            if len(self._items) >= self.max_approvals:
                raise ApprovalCapacityError("Too many approvals are waiting; refusing the call")
            pending_here = sum(1 for a in self._items.values() if a.session == session and a.status == PENDING)
            if pending_here >= self.max_pending_per_session:
                raise ApprovalCapacityError(
                    f"This session already has {pending_here} approvals waiting; refusing the call")
            preview = flatten(arguments)
            sha = arguments_sha256(tool, server, arguments)
            # Diff against the most recent earlier approval for the same tool in
            # this session (for example: A was approved, now B changes one field).
            previous = max(
                (a for a in self._items.values()
                 if a.session == session and a.tool == tool and a.server == server and a.arguments_sha256 != sha),
                key=lambda a: a.created_at, default=None,
            )
            approval = PendingApproval(
                id="apr_" + secrets.token_urlsafe(12),
                session=session, agent=agent, tool=tool, server=server,
                arguments_sha256=sha, arguments_preview=preview, decision=decision,
                created_at=now, expires_at=now + timeout_seconds,
                timeout_seconds=timeout_seconds, grant_ttl_seconds=grant_ttl_seconds,
                diff_from=previous.id if previous else "",
                diff=diff(previous.arguments_preview, preview) if previous else [],
            )
            self._items[approval.id] = approval
            self._events[approval.id] = asyncio.Event()
            self._arm_timer(approval)
        await self._notify(approval, PENDING)
        return approval

    async def get(self, approval_id: str) -> PendingApproval | None:
        approval = self._items.get(approval_id)
        if approval is not None:
            await self._expire_if_due(approval)
        return approval

    async def resolve(self, approval_id, *, approve, by, note="", reason=""):
        async with self._lock:
            approval = self._items.get(approval_id)
            if approval is None:
                raise KeyError(approval_id)
            if approval.status != PENDING:
                raise ApprovalNotPending(f"Approval {approval_id} is already {approval.status}")
            now = self._clock()
            if approve and now >= approval.expires_at:
                # Too late: the timeout already decided, even if the timer has not fired yet.
                approve, by, reason, note = False, "guardian", "timeout", ""
            approval.status = APPROVED if approve else DENIED
            approval.reason = reason or ("approved" if approve else "denied by approver")
            approval.note = (note or "")[:1000]
            approval.resolved_by = (by or "")[:200]
            approval.resolved_at = now
            timer = self._timers.pop(approval_id, None)
            if timer is not None:
                timer.cancel()
            self._events[approval_id].set()
        await self._notify(approval, approval.status)
        return approval

    async def wait(self, approval_id, timeout):
        approval = await self.get(approval_id)
        if approval is None or approval.status != PENDING or timeout <= 0:
            return approval
        event = self._events.get(approval_id)
        if event is not None:
            try:
                await asyncio.wait_for(event.wait(), timeout=min(timeout, max(0.0, approval.expires_at - self._clock()) + 1))
            except asyncio.TimeoutError:
                pass
        return await self.get(approval_id)

    async def find(self, *, session, agent, sha256):
        now = self._clock()
        best = None
        for a in list(self._items.values()):
            if a.session != session or a.agent != agent or a.arguments_sha256 != sha256:
                continue
            await self._expire_if_due(a)
            if a.status == PENDING:
                return a
            if a.usable(now) and (best is None or (a.resolved_at or 0) > (best.resolved_at or 0)):
                best = a
        return best

    async def use(self, approval_id):
        async with self._lock:
            approval = self._items.get(approval_id)
            if approval is None or not approval.usable(self._clock()):
                return False
            approval.uses += 1
        await self._notify(approval, "used")
        return True

    async def list(self, *, session, status=None):
        out = []
        for a in list(self._items.values()):
            if a.session != session:
                continue
            await self._expire_if_due(a)
            if status is None or a.status == status:
                out.append(a)
        return sorted(out, key=lambda a: a.created_at)

    async def close(self) -> None:
        for timer in self._timers.values():
            timer.cancel()
        self._timers.clear()
