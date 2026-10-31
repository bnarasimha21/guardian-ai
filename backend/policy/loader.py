"""Load the policy file and reload it when it changes.

``PolicyStore.get()`` is called on every decision. It stats the file (cheap)
and re-reads it when the modification time, size or inode changed, and in any
case at most every ``recheck_seconds`` it re-hashes the content, so an edit
that keeps the same mtime (coarse filesystem clocks) is still picked up.

* At startup a missing or invalid file raises PolicyError: the server must not
  start without a policy.
* After startup an invalid edit is logged and the last good policy stays in
  force, with the error exposed as ``last_error``. A half-saved file never
  turns into "allow everything".
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from .models import Policy

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_FILE = REPO_ROOT / "policies" / "default.yaml"
MAX_POLICY_BYTES = 1_000_000


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    path: str
    sha256: str
    loaded_at: float


def resolve_policy_path(configured: str | None) -> Path:
    if not configured:
        return DEFAULT_POLICY_FILE
    p = Path(configured).expanduser()
    if not p.is_absolute() and not p.exists() and (REPO_ROOT / p).exists():
        p = REPO_ROOT / p
    return p


def parse_policy(text: str, source: str = "<policy>") -> Policy:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: the policy must be a mapping with 'version: 1' and 'rules'")
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(x) for x in err['loc']) or '(root)'}: {err['msg']}" for err in exc.errors()
        )
        raise PolicyError(f"{source}: {problems}") from exc


class PolicyStore:
    def __init__(self, path: str | os.PathLike | None = None, *, recheck_seconds: float = 1.0) -> None:
        self.path = resolve_policy_path(str(path) if path else None)
        self.recheck_seconds = recheck_seconds
        self.last_error: str | None = None
        self._lock = threading.Lock()
        self._stat_key: tuple | None = None
        self._last_hash_check = 0.0
        self._current: LoadedPolicy | None = None
        self._current = self._load(initial=True)

    # -- internals -------------------------------------------------------

    def _read(self) -> tuple[bytes, tuple]:
        st = self.path.stat()
        if st.st_size > MAX_POLICY_BYTES:
            raise PolicyError(f"{self.path}: policy file is larger than {MAX_POLICY_BYTES} bytes")
        data = self.path.read_bytes()
        return data, (st.st_mtime_ns, st.st_size, st.st_ino)

    def _load(self, *, initial: bool) -> LoadedPolicy:
        try:
            data, key = self._read()
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {self.path}: {exc}") from exc
        digest = hashlib.sha256(data).hexdigest()
        self._stat_key = key
        self._last_hash_check = time.monotonic()
        if self._current is not None and digest == self._current.sha256:
            self.last_error = None
            return self._current
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError(f"{self.path}: not UTF-8: {exc}") from exc
        policy = parse_policy(text, str(self.path))
        loaded = LoadedPolicy(policy=policy, path=str(self.path), sha256=digest, loaded_at=time.time())
        if not initial:
            logger.info("Policy reloaded from %s (sha256 %s, %d rules)", self.path, digest[:12], len(policy.rules))
        else:
            logger.info("Policy loaded from %s (sha256 %s, %d rules)", self.path, digest[:12], len(policy.rules))
        self.last_error = None
        return loaded

    # -- public ----------------------------------------------------------

    def get(self) -> LoadedPolicy:
        """The policy in force, reloading first if the file changed."""
        with self._lock:
            try:
                st = self.path.stat()
                key = (st.st_mtime_ns, st.st_size, st.st_ino)
            except OSError as exc:
                self._note_error(f"cannot stat policy file {self.path}: {exc}")
                return self._current  # type: ignore[return-value]
            due = time.monotonic() - self._last_hash_check >= self.recheck_seconds
            if key != self._stat_key or due:
                try:
                    self._current = self._load(initial=False)
                except PolicyError as exc:
                    self._stat_key = key
                    self._last_hash_check = time.monotonic()
                    self._note_error(str(exc))
            return self._current  # type: ignore[return-value]

    def _note_error(self, message: str) -> None:
        if message != self.last_error:
            logger.error("Policy reload failed, keeping the last good policy: %s", message)
        self.last_error = message
