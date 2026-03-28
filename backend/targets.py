"""Persistent target app management. Stores registered apps in a JSON file."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

TARGETS_FILE = Path(__file__).parent.parent / "targets.json"


@dataclass
class TargetApp:
    name: str
    ws_url: str
    status: str = "disconnected"  # disconnected, connecting, connected


class TargetStore:
    """Manages registered target apps."""

    def __init__(self) -> None:
        self.targets: dict[str, TargetApp] = {}
        self._load()

    def _load(self) -> None:
        if TARGETS_FILE.exists():
            try:
                data = json.loads(TARGETS_FILE.read_text())
                for item in data:
                    t = TargetApp(**item)
                    t.status = "disconnected"
                    self.targets[t.name] = t
                logger.info("Loaded %d targets from %s", len(self.targets), TARGETS_FILE)
            except Exception as e:
                logger.error("Failed to load targets: %s", e)

    def _save(self) -> None:
        data = [{"name": t.name, "ws_url": t.ws_url} for t in self.targets.values()]
        TARGETS_FILE.write_text(json.dumps(data, indent=2))

    def add(self, name: str, ws_url: str) -> TargetApp:
        target = TargetApp(name=name, ws_url=ws_url)
        self.targets[name] = target
        self._save()
        return target

    def remove(self, name: str) -> bool:
        if name in self.targets:
            del self.targets[name]
            self._save()
            return True
        return False

    def get(self, name: str) -> TargetApp | None:
        return self.targets.get(name)

    def list_all(self) -> list[TargetApp]:
        return list(self.targets.values())

    def set_status(self, name: str, status: str) -> None:
        if name in self.targets:
            self.targets[name].status = status


target_store = TargetStore()
