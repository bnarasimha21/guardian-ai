"""Pinned tool definitions (rug-pull protection).

The first time the gateway sees a clean tool it records a SHA-256 of the
definition (name, title, description, input and output schema, annotations).
If a later listing returns a different hash, the tool is hidden and the new
hash is kept as ``pending_sha256`` until an operator approves it with
``guardian-mcp --config gateway.yaml pins approve <server.tool>``.

The file is plain JSON, written atomically (temp file and rename). Two gateway
processes sharing one pins file can overwrite each other's new pins; give each
gateway its own file if that matters.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

FORMAT_VERSION = 1


def definition_sha256(definition: dict[str, Any]) -> str:
    """Hash of a tool definition as the upstream sent it, minus transport metadata."""
    material = {k: v for k, v in definition.items() if k not in ("_meta", "meta")}
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class PinError(Exception):
    pass


class PinStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self._pins: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            self._pins = {}
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            # A corrupt pins file must not silently reset trust to "first use".
            raise PinError(f"cannot read pins file {self.path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
            raise PinError(f"pins file {self.path} has an unexpected shape")
        self._pins = data["tools"]

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"version": FORMAT_VERSION, "tools": self._pins}, indent=2, sort_keys=True)
        fd, tmp = tempfile.mkstemp(prefix=".pins-", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def get(self, name: str) -> dict[str, Any] | None:
        return self._pins.get(name)

    def all(self) -> dict[str, dict[str, Any]]:
        return dict(self._pins)

    def check(self, name: str, sha: str, description: str = "") -> str:
        """Compare a listed definition with its pin.

        Returns ``"pinned"`` (new tool, now pinned), ``"match"`` or ``"changed"``.
        A changed definition records ``pending_sha256`` for ``approve``.
        """
        pin = self._pins.get(name)
        now = time.time()
        if pin is None:
            self._pins[name] = {"sha256": sha, "pinned_at": now, "description": description[:500]}
            self._save()
            return "pinned"
        if pin.get("sha256") == sha:
            if pin.get("pending_sha256"):
                pin.pop("pending_sha256", None)
                pin.pop("pending_description", None)
                pin.pop("changed_at", None)
                self._save()
            return "match"
        if pin.get("pending_sha256") != sha:
            pin["pending_sha256"] = sha
            pin["pending_description"] = description[:500]
            pin["changed_at"] = now
            self._save()
        return "changed"

    def approve(self, name: str) -> dict[str, Any]:
        """Accept the pending definition of ``name`` as the new pin."""
        self.reload()
        pin = self._pins.get(name)
        if pin is None:
            raise PinError(f"no pin for {name!r}")
        if not pin.get("pending_sha256"):
            raise PinError(f"{name!r} has no changed definition waiting for approval")
        pin["previous_sha256"] = pin["sha256"]
        pin["sha256"] = pin.pop("pending_sha256")
        pin["description"] = pin.pop("pending_description", "")
        pin.pop("changed_at", None)
        pin["pinned_at"] = time.time()
        self._save()
        return pin

    def forget(self, name: str) -> None:
        self.reload()
        if self._pins.pop(name, None) is None:
            raise PinError(f"no pin for {name!r}")
        self._save()
