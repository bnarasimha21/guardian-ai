"""Optional usage analytics to Supabase.

Off unless ``GUARDIAN_USAGE_LOGGING`` is true and ``SUPABASE_URL`` and
``SUPABASE_ANON_KEY`` are set. The rows include session ids, IP addresses and
user agents, so keep the table unreadable by the anon role (see
create_table.sql). Decisions are traced with OpenTelemetry instead (see
backend/telemetry.py); this logger is a side channel for the hosted demo.

Calls are fire-and-forget: a failure is logged as a warning and never affects
a decision.
"""

import logging
import os

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "")
TABLE = "guardian_ai_usage"

# Tests replace this with an httpx.MockTransport.
transport: httpx.AsyncBaseTransport | None = None


def enabled() -> bool:
    return bool(settings.guardian_usage_logging and SUPABASE_URL and SUPABASE_KEY)


async def log_event(
    event_type: str,
    session_id: str = "",
    app_name: str = "",
    app_url: str = "",
    rule_name: str = "",
    owasp_id: str = "",
    threat_level: str = "",
    reason: str = "",
    total_events_checked: int = 0,
    total_blocked: int = 0,
    user_agent: str = "",
    ip_address: str = "",
):
    """Insert one usage row, if usage logging is enabled."""
    if not enabled():
        return

    row = {
        "event_type": event_type,
        "session_id": session_id,
        "app_name": app_name,
        "app_url": app_url,
        "rule_name": rule_name,
        "owasp_id": owasp_id,
        "threat_level": threat_level,
        "reason": reason,
        "total_events_checked": total_events_checked,
        "total_blocked": total_blocked,
        "user_agent": user_agent,
        "ip_address": ip_address,
    }

    try:
        async with httpx.AsyncClient(timeout=5, transport=transport) as client:
            resp = await client.post(
                f"{SUPABASE_URL}/rest/v1/{TABLE}",
                json=row,
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
            )
        if resp.status_code >= 400:
            logger.warning("usage log rejected by Supabase: HTTP %s", resp.status_code)
    except Exception as exc:
        logger.warning("usage log to Supabase failed: %s", type(exc).__name__)
