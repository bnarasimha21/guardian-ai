"""One policy per tenant on top of a shared base.

A tenant is a team with its own agents. With ``GUARDIAN_TENANT_POLICIES_DIR``
set, a tenant ``payments`` gets the base policy followed by the rules in
``<dir>/payments.yaml``::

    version: 1
    rules:
      - id: payments-refund
        match: {tool: "payments.refund"}
        effect: require_approval

How the two combine. The base rules are checked first, then the tenant's, and
the first match decides, as in a single file. So:

* a base ``deny`` or ``require_approval`` cannot be overridden by a tenant;
* a base ``allow`` applies to every tenant;
* a tenant decides only what the base leaves undecided, and whatever neither
  matches gets the base ``default_effect``.

``mode``, the defaults, the approval settings and ``untrusted_inputs`` come
from the base alone. A tenant file may hold ``version`` and ``rules`` and
nothing else, so a tenant cannot switch itself to monitor mode.

Which tenant a caller belongs to comes from its API key name, never from the
request: ``payments.checkout-agent`` is tenant ``payments``, and a name with
no dot is its own tenant. Without API keys there are no tenants.

Failure is closed. A tenant file that does not parse at startup stops the
server. One that breaks later keeps that tenant's last good policy; if there
is none (the file was added broken), that tenant's calls are refused, and
other tenants are unaffected.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, ValidationError

from .loader import MAX_POLICY_BYTES, LoadedPolicy, PolicyError, PolicyStore
from .models import Policy, Rule, _Strict

logger = logging.getLogger(__name__)

TENANT_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
SUFFIXES = (".yaml", ".yml")


class TenantRules(_Strict):
    """What a tenant file may contain."""

    version: Literal[1]
    rules: list[Rule] = Field(default_factory=list)


def tenant_of(principal: str | None) -> str | None:
    """The tenant an API key name belongs to: the part before the first dot."""
    if not principal:
        return None
    name = principal.split(".", 1)[0]
    return name if TENANT_NAME.match(name) else None


def parse_tenant_rules(text: str, source: str = "<tenant policy>") -> TenantRules:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: a tenant policy must be a mapping with 'version: 1' and 'rules'")
    try:
        return TenantRules.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(x) for x in err['loc']) or '(root)'}: {err['msg']}" for err in exc.errors()
        )
        raise PolicyError(f"{source}: {problems}") from exc


def combine(base: LoadedPolicy, tenant: TenantRules, tenant_sha256: str, path: str) -> LoadedPolicy:
    """The base policy with the tenant's rules after its own."""
    base_ids = {rule.id for rule in base.policy.rules}
    clash = sorted(rule.id for rule in tenant.rules if rule.id in base_ids)
    if clash:
        raise PolicyError(f"{path}: rule id(s) already used by the base policy: {', '.join(clash)}")
    try:
        policy = Policy.model_validate({
            **base.policy.model_dump(by_alias=True, exclude={"rules"}),
            "rules": [r.model_dump(by_alias=True) for r in [*base.policy.rules, *tenant.rules]],
        })
    except ValidationError as exc:  # duplicate ids inside the tenant file, for one
        raise PolicyError(f"{path}: {exc.errors()[0]['msg']}") from exc
    digest = hashlib.sha256(f"{base.sha256}:{tenant_sha256}".encode()).hexdigest()
    return LoadedPolicy(policy=policy, path=path, sha256=digest, loaded_at=time.time())


@dataclass
class _Entry:
    stat_key: tuple | None  # None: no file for this tenant
    tenant_sha256: str
    base_sha256: str
    loaded: LoadedPolicy | None
    error: str | None = None
    checked_at: float = 0.0


class TenantPolicies:
    """The policy in force for each tenant. ``get()`` is called on every decision."""

    def __init__(self, base: PolicyStore, directory: str | os.PathLike | None = None, *,
                 recheck_seconds: float = 1.0) -> None:
        self.base = base
        self.directory = Path(directory).expanduser() if directory else None
        self.recheck_seconds = recheck_seconds
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}
        if self.directory is not None:
            if not self.directory.is_dir():
                raise PolicyError(f"tenant policy directory {self.directory} does not exist")
            # Every tenant file must load at startup: a typo should stop the
            # server, not sit there until that tenant's first call.
            for name in self.tenants():
                self._load(name, self.base.get(), initial=True)

    # -- internals -----------------------------------------------------------

    def _file(self, tenant: str) -> Path | None:
        if self.directory is None or not TENANT_NAME.match(tenant):
            return None
        for suffix in SUFFIXES:
            path = self.directory / f"{tenant}{suffix}"
            if path.is_file():
                return path
        return None

    def _load(self, tenant: str, base: LoadedPolicy, *, initial: bool) -> _Entry:
        path = self._file(tenant)
        previous = self._entries.get(tenant)
        if path is None:
            entry = _Entry(None, "", base.sha256, base, checked_at=time.monotonic())
            self._entries[tenant] = entry
            return entry
        try:
            st = path.stat()
            if st.st_size > MAX_POLICY_BYTES:
                raise PolicyError(f"{path}: policy file is larger than {MAX_POLICY_BYTES} bytes")
            data = path.read_bytes()
            key = (str(path), st.st_mtime_ns, st.st_size, st.st_ino)
            digest = hashlib.sha256(data).hexdigest()
            if (previous is not None and previous.loaded is not None and previous.error is None
                    and previous.tenant_sha256 == digest and previous.base_sha256 == base.sha256):
                previous.stat_key, previous.checked_at = key, time.monotonic()
                return previous
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PolicyError(f"{path}: not UTF-8: {exc}") from exc
            loaded = combine(base, parse_tenant_rules(text, str(path)), digest, str(path))
        except (OSError, PolicyError) as exc:
            message = str(exc) if isinstance(exc, PolicyError) else f"cannot read tenant policy {path}: {exc}"
            if initial:
                raise PolicyError(message) from exc
            last_good = previous.loaded if previous is not None else None
            if previous is None or previous.error != message:
                logger.error("Tenant policy for '%s' failed to load, %s: %s", tenant,
                             "keeping the last good one" if last_good else "refusing its calls", message)
            entry = _Entry(None, "", base.sha256, last_good, error=message, checked_at=time.monotonic())
            # Keep the stat key unknown so the next check reads the file again.
            self._entries[tenant] = entry
            return entry
        logger.info("Tenant policy for '%s' loaded from %s (sha256 %s, %d base + %d tenant rules)", tenant, path,
                    loaded.sha256[:12], len(base.policy.rules), len(loaded.policy.rules) - len(base.policy.rules))
        entry = _Entry(key, digest, base.sha256, loaded, checked_at=time.monotonic())
        self._entries[tenant] = entry
        return entry

    def _current(self, tenant: str) -> _Entry:
        base = self.base.get()
        with self._lock:
            entry = self._entries.get(tenant)
            if entry is not None and entry.error is None and entry.base_sha256 == base.sha256:
                path = self._file(tenant)
                key = None
                if path is not None:
                    try:
                        st = path.stat()
                        key = (str(path), st.st_mtime_ns, st.st_size, st.st_ino)
                    except OSError:
                        key = ("unreadable",)
                # Like the base store: a changed file reloads at once, and the
                # content is re-hashed at most every recheck_seconds anyway.
                if key == entry.stat_key and time.monotonic() - entry.checked_at < self.recheck_seconds:
                    return entry
            return self._load(tenant, base, initial=False)

    # -- public --------------------------------------------------------------

    def tenants(self) -> list[str]:
        """Tenants that have a policy file."""
        if self.directory is None:
            return []
        names = {p.stem for p in self.directory.iterdir()
                 if p.is_file() and p.suffix in SUFFIXES and TENANT_NAME.match(p.stem)}
        return sorted(names)

    def get(self, tenant: str | None) -> LoadedPolicy:
        """The policy for ``tenant`` (None, or no tenant directory: the base policy)."""
        if tenant is None or self.directory is None:
            return self.base.get()
        entry = self._current(tenant)
        if entry.loaded is None:
            raise PolicyError(f"tenant '{tenant}' has no usable policy: {entry.error}")
        return entry.loaded

    def last_error(self, tenant: str | None) -> str | None:
        if tenant is None or self.directory is None:
            return self.base.last_error
        entry = self._entries.get(tenant)
        return (entry.error if entry is not None else None) or self.base.last_error
