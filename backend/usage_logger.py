"""Log usage to Supabase for analytics. Non-blocking, fails silently."""

import os
import logging

import httpx

logger = logging.getLogger(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "")
TABLE = "guardian_ai_usage"


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
    """Log a usage event to Supabase. Non-blocking, fails silently."""
    if not SUPABASE_URL or not SUPABASE_KEY:
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
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{SUPABASE_URL}/rest/v1/{TABLE}",
                json=row,
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
            )
    except Exception:
        pass
