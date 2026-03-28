"""Per-session target app management. Each browser session gets isolated targets."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

TARGETS_DIR = Path(__file__).parent.parent / "sessions"


@dataclass
class TargetApp:
    name: str
    ws_url: str
    status: str = "disconnected"


class SessionStore:
    """Manages targets per session. Each session has its own JSON file."""

    def __init__(self) -> None:
        TARGETS_DIR.mkdir(exist_ok=True)
        self._sessions: dict[str, dict[str, TargetApp]] = {}

    def _file(self, session_id: str) -> Path:
        # Sanitize session ID to prevent path traversal
        safe_id = "".join(c for c in session_id if c.isalnum() or c in "-_")
        return TARGETS_DIR / f"{safe_id}.json"

    def _load(self, session_id: str) -> dict[str, TargetApp]:
        if session_id in self._sessions:
            return self._sessions[session_id]

        targets: dict[str, TargetApp] = {}
        f = self._file(session_id)
        if f.exists():
            try:
                data = json.loads(f.read_text())
                for item in data:
                    t = TargetApp(**item)
                    t.status = "disconnected"
                    targets[t.name] = t
            except Exception as e:
                logger.error("Failed to load session %s: %s", session_id, e)

        self._sessions[session_id] = targets
        return targets

    def _save(self, session_id: str) -> None:
        targets = self._sessions.get(session_id, {})
        data = [{"name": t.name, "ws_url": t.ws_url} for t in targets.values()]
        self._file(session_id).write_text(json.dumps(data, indent=2))

    def add(self, session_id: str, name: str, ws_url: str) -> TargetApp:
        targets = self._load(session_id)
        target = TargetApp(name=name, ws_url=ws_url)
        targets[name] = target
        self._save(session_id)
        return target

    def remove(self, session_id: str, name: str) -> bool:
        targets = self._load(session_id)
        if name in targets:
            del targets[name]
            self._save(session_id)
            return True
        return False

    def get(self, session_id: str, name: str) -> TargetApp | None:
        return self._load(session_id).get(name)

    def list_all(self, session_id: str) -> list[TargetApp]:
        return list(self._load(session_id).values())

    def set_status(self, session_id: str, name: str, status: str) -> None:
        targets = self._load(session_id)
        if name in targets:
            targets[name].status = status


session_store = SessionStore()
