"""Outbound address checks for URLs that GuardianAI itself connects to.

GuardianAI makes server-side requests in two places: ``POST /api/targets/verify``
and the tap observer that connects to a registered app's ``/ws-observe``. Both
take a URL from an unauthenticated browser, so without these checks the hosted
demo could be pointed at ``169.254.169.254`` or anything else on its private
network.

The rules:

* only the schemes the caller allows (``ws`` and ``wss`` for targets);
* no credentials in the URL;
* the host is resolved once, and every resolved address must be public
  (``ipaddress`` ``is_global``, after unwrapping IPv4-mapped, 6to4 and NAT64
  IPv6 forms), otherwise the URL is refused;
* the caller then connects to the address that was checked (``pinned_ip``), so a
  second DNS answer cannot swap in a private address (DNS rebinding).

``classify_host_literal`` is also used by the SSRF detector, without DNS.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

METADATA_HOSTNAMES = {
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
}
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

DEFAULT_PORTS = {"http": 80, "ws": 80, "https": 443, "wss": 443}


class TargetRejected(Exception):
    """The URL must not be fetched. ``code`` is a stable machine-readable value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def parse_ipv4_loose(text: str) -> ipaddress.IPv4Address | None:
    """Parse IPv4 the way inet_aton(3) does, which is what many HTTP stacks accept.

    Handles dotted quads, integers (``2130706433``), hex (``0x7f000001``),
    octal parts (``0177.0.0.1``) and short forms (``127.1``). Returns None for
    anything that is not one of those.
    """
    if not text or len(text) > 64:
        return None
    parts = text.split(".")
    if len(parts) > 4 or any(p == "" for p in parts):
        return None
    values: list[int] = []
    for part in parts:
        p = part.lower()
        try:
            if p.startswith("0x"):
                if len(p) == 2:
                    value = 0
                else:
                    value = int(p[2:], 16)
            elif len(p) > 1 and p.startswith("0"):
                value = int(p[1:], 8)
            else:
                if not p.isdigit():
                    return None
                value = int(p, 10)
        except ValueError:
            return None
        values.append(value)
    # inet_aton: the last part fills the remaining bytes.
    limits = {1: [2**32], 2: [256, 2**24], 3: [256, 256, 2**16], 4: [256, 256, 256, 256]}[len(values)]
    total = 0
    for i, (value, limit) in enumerate(zip(values, limits)):
        if value >= limit:
            return None
        if i < len(values) - 1:
            total = (total << 8) | value
        else:
            remaining_bits = {1: 32, 2: 24, 3: 16, 4: 8}[len(values)]
            total = (total << remaining_bits) | value
    return ipaddress.IPv4Address(total)


def parse_ip_literal(host: str) -> IPAddress | None:
    """Parse a host that is an IP literal in any common form, else None."""
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        return None
    if ":" in h:
        try:
            return ipaddress.IPv6Address(h.split("%", 1)[0])
        except ValueError:
            return None
    return parse_ipv4_loose(h)


def classify_ip(ip: IPAddress) -> str | None:
    """Return why an address must not be contacted, or None if it is public."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return classify_ip(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            inner = classify_ip(ip.sixtofour)
            if inner:
                return inner
        if ip in _NAT64:
            inner = classify_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
            if inner:
                return inner
    if ip in METADATA_IPS:
        return "cloud metadata endpoint"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_private:
        return "private network address"
    if ip.is_reserved:
        return "reserved address"
    if not ip.is_global:
        return "non-public address"
    return None


def classify_host_literal(host: str) -> str | None:
    """Classify a hostname or IP literal without DNS. None means not known-internal."""
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        return None
    if h == "localhost" or h.endswith(".localhost"):
        return "localhost"
    if h in METADATA_HOSTNAMES:
        return "cloud metadata hostname"
    if h.endswith(".internal") or h.endswith(".local") or h.endswith(".home.arpa"):
        return "internal hostname"
    ip = parse_ip_literal(h)
    if ip is not None:
        return classify_ip(ip)
    return None


async def system_resolve(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


@dataclass
class CheckedTarget:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    pinned_ip: str
    resolved: list[str] = field(default_factory=list)

    @property
    def secure(self) -> bool:
        return self.scheme in ("https", "wss")

    @property
    def host_header(self) -> str:
        default = DEFAULT_PORTS.get(self.scheme)
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == default else f"{host}:{self.port}"

    def pinned_http_url(self) -> str:
        """http(s) URL that connects to the checked IP instead of re-resolving."""
        scheme = "https" if self.secure else "http"
        ip = f"[{self.pinned_ip}]" if ":" in self.pinned_ip else self.pinned_ip
        return f"{scheme}://{ip}:{self.port}{self.path}"


async def check_target_url(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("ws", "wss"),
    allow_private: bool = False,
    resolver: Resolver | None = None,
    resolve_timeout: float = 5.0,
) -> CheckedTarget:
    """Validate a URL GuardianAI is about to connect to. Raises TargetRejected."""
    if not isinstance(url, str) or not url.strip():
        raise TargetRejected("invalid_url", "No URL provided.")
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise TargetRejected("invalid_url", "The URL could not be parsed.")
    scheme = parts.scheme.lower()
    if scheme not in allowed_schemes:
        raise TargetRejected(
            "invalid_scheme",
            f"Only {', '.join(s + '://' for s in allowed_schemes)} URLs are allowed.",
        )
    if parts.username is not None or parts.password is not None:
        raise TargetRejected("invalid_url", "URLs with embedded credentials are not allowed.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise TargetRejected("invalid_url", "The URL has no host.")
    port = port or DEFAULT_PORTS[scheme]
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    if not allow_private:
        reason = classify_host_literal(host)
        if reason:
            raise TargetRejected(
                "blocked_address",
                f"Refusing to connect to {host}: {reason}. GuardianAI only connects to public addresses.",
            )

    literal = parse_ip_literal(host)
    if literal is not None:
        resolved = [str(literal)]
    else:
        try:
            resolved = await asyncio.wait_for((resolver or system_resolve)(host, port), resolve_timeout)
        except (OSError, asyncio.TimeoutError, UnicodeError) as exc:
            raise TargetRejected("dns_failed", f"Could not resolve {host}: {exc}")
        if not resolved:
            raise TargetRejected("dns_failed", f"Could not resolve {host}.")

    for addr in resolved:
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            raise TargetRejected("dns_failed", f"Resolver returned an invalid address for {host}.")
        reason = classify_ip(ip)
        if reason and not allow_private:
            raise TargetRejected(
                "blocked_address",
                f"Refusing to connect to {host}: it resolves to {addr} ({reason}). "
                "GuardianAI only connects to public addresses.",
            )

    # Prefer IPv4 for the pinned connection: many hosts publish AAAA records but
    # only listen on IPv4, and every address was checked above either way.
    ordered = sorted(resolved, key=lambda a: ":" in a)
    return CheckedTarget(
        url=url.strip(), scheme=scheme, host=host, port=port, path=path,
        pinned_ip=ordered[0].split("%", 1)[0], resolved=list(resolved),
    )
