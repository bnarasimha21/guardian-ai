"""API keys for the check API and approvers.

Keys come from the environment as ``name=key,name2=key2``. The name is the
caller's identity: an authenticated /api/check call runs in session
``app:<name>`` and policy ``agent`` matches use the name, so a caller cannot
claim another app's session or identity by sending a different header.
"""

from __future__ import annotations

import hmac
import re

APP_SESSION_PREFIX = "app:"
_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
MIN_KEY_LENGTH = 16


class KeyConfigError(ValueError):
    pass


def parse_keys(spec: str, *, env_name: str = "GUARDIAN_API_KEYS") -> dict[str, str]:
    """Parse ``name=key,...`` into {name: key}. Raises KeyConfigError."""
    keys: dict[str, str] = {}
    if not spec or not spec.strip():
        return keys
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        name, sep, key = item.partition("=")
        name, key = name.strip(), key.strip()
        if not sep or not _NAME.match(name):
            raise KeyConfigError(f"{env_name}: each entry must be name=key with a name of letters, digits, _ . -")
        if len(key) < MIN_KEY_LENGTH:
            raise KeyConfigError(f"{env_name}: the key for '{name}' must be at least {MIN_KEY_LENGTH} characters")
        if name in keys:
            raise KeyConfigError(f"{env_name}: duplicate name '{name}'")
        keys[name] = key
    return keys


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def match_key(token: str | None, keys: dict[str, str]) -> str | None:
    """Name whose key equals token (constant-time per key), else None."""
    if not token:
        return None
    found = None
    for name, key in keys.items():
        if hmac.compare_digest(token.encode(), key.encode()):
            found = name
    return found
