"""The queue side of a require_approval decision, shared by /api/check and the MCP gateway.

For one call (bound to session, agent and an arguments hash) there are three
outcomes:

* a usable approved grant exists: it is consumed and the call may run;
* the same call is already waiting for a human: report that approval again;
* otherwise a new pending approval is opened.

The caller turns the outcome into its own response (HTTP 200/202/429, or an
MCP tool result).
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.guardian.schema import ToolCall

from .store import ApprovalCapacityError, ApprovalStore, PendingApproval, arguments_sha256

GRANTED = "granted"
WAITING = "waiting"
CREATED = "created"
REFUSED = "refused"


@dataclass
class QueueOutcome:
    status: str                     # granted | waiting | created | refused
    approval: PendingApproval | None
    arguments_sha256: str
    error: str = ""


async def queue_for_approval(store: ApprovalStore, decision, call: ToolCall, *, session: str,
                             agent: str) -> QueueOutcome:
    sha = arguments_sha256(call.name, call.server, call.arguments)
    settings_ = decision.approval
    try:
        # One atomic step in the store: checking for a grant or a waiting
        # approval and opening a new one separately let two identical calls
        # arriving together each open their own approval.
        status, approval = await store.find_or_create(
            session=session, agent=agent, tool=call.name, server=call.server, arguments=call.arguments,
            decision=decision.to_dict(),
            timeout_seconds=settings_.timeout_seconds if settings_ else 120,
            grant_ttl_seconds=settings_.grant_ttl_seconds if settings_ else 0,
        )
    except ApprovalCapacityError as exc:
        return QueueOutcome(REFUSED, None, sha, error=str(exc))
    return QueueOutcome({"granted": GRANTED, "waiting": WAITING, "created": CREATED}[status], approval, sha)
