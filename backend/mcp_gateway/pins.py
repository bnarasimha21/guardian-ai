"""Pinned tool definitions (rug-pull protection).

The first time the gateway sees a clean tool it records a SHA-256 of the
definition (name, title, description, input and output schema, annotations).
If a later listing returns a different hash, the tool is hidden and the new
hash is kept as ``pending_sha256`` until an operator approves it with
``guardian-mcp --config gateway.yaml pins approve <server.tool> <sha256>``.

Approval names the full hash being approved, so a definition that changes
again between ``pins list`` (where the operator read the diff) and ``pins
approve`` is not accepted by mistake. A prefix is not enough: an upstream can
search for a second definition whose hash starts with the same 8 or 12 hex
characters in minutes. The pinned and pending definitions are stored in
full so ``pins list`` can show what changed.

The file is plain JSON, written atomically (temp file and rename). Two gateway
processes sharing one pins file can overwrite each other's new pins; give each
gateway its own file if that matters.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

FORMAT_VERSION = 1
SHA256_HEX = 64  # `approve` must quote the whole pending hash


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

    def check(self, name: str, sha: str, description: str = "",
              definition: dict[str, Any] | None = None) -> str:
        """Compare a listed definition with its pin.

        Returns ``"pinned"`` (new tool, now pinned), ``"match"`` or ``"changed"``.
        A changed definition records ``pending_sha256`` (and the definition
        itself) for ``approve``.
        """
        pin = self._pins.get(name)
        now = time.time()
        if pin is None:
            self._pins[name] = {"sha256": sha, "pinned_at": now, "description": description[:500],
                                "definition": definition}
            self._save()
            return "pinned"
        if pin.get("sha256") == sha:
            dirty = False
            if pin.get("pending_sha256"):
                for key in ("pending_sha256", "pending_description", "pending_definition", "changed_at"):
                    pin.pop(key, None)
                dirty = True
            if definition is not None and pin.get("definition") is None:
                pin["definition"] = definition  # pinned before definitions were kept
                dirty = True
            if dirty:
                self._save()
            return "match"
        if pin.get("pending_sha256") != sha:
            pin["pending_sha256"] = sha
            pin["pending_description"] = description[:500]
            pin["pending_definition"] = definition
            pin["changed_at"] = now
            self._save()
        return "changed"

    def diff(self, name: str) -> str:
        """Unified diff of the pinned and the pending definition of ``name``."""
        pin = self._pins.get(name) or {}
        if not pin.get("pending_sha256"):
            return ""
        old, new = pin.get("definition"), pin.get("pending_definition")
        if old is None or new is None:
            return "(the full definitions were not recorded; compare with the upstream before approving)"

        def lines(d: Any) -> list[str]:
            return json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False, default=str).splitlines()

        return "\n".join(difflib.unified_diff(lines(old), lines(new), f"pinned {pin['sha256'][:12]}",
                                               f"now {pin['pending_sha256'][:12]}", lineterm=""))

    def approve(self, name: str, sha256: str) -> dict[str, Any]:
        """Accept the pending definition of ``name`` as the new pin.

        ``sha256`` must be the whole pending hash the operator reviewed; if
        the definition changed again since, the pending hash differs and
        nothing is approved.
        """
        wanted = (sha256 or "").strip().lower()
        if len(wanted) != SHA256_HEX or any(c not in "0123456789abcdef" for c in wanted):
            raise PinError(f"give the whole new hash ({SHA256_HEX} hex characters) shown by `pins list`")
        self.reload()
        pin = self._pins.get(name)
        if pin is None:
            raise PinError(f"no pin for {name!r}")
        pending = pin.get("pending_sha256")
        if not pending:
            raise PinError(f"{name!r} has no changed definition waiting for approval")
        if pending != wanted:
            raise PinError(f"{name!r} is now waiting on {pending[:12]}, not {wanted[:12]}: the definition changed "
                           "again; run `pins list` and review it before approving")
        pin["previous_sha256"] = pin["sha256"]
        pin["sha256"] = pin.pop("pending_sha256")
        pin["description"] = pin.pop("pending_description", "")
        pin["definition"] = pin.pop("pending_definition", None)
        pin.pop("changed_at", None)
        pin["pinned_at"] = time.time()
        self._save()
        return pin

    def forget(self, name: str) -> None:
        self.reload()
        if self._pins.pop(name, None) is None:
            raise PinError(f"no pin for {name!r}")
        self._save()
