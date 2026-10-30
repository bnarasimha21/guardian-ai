"""Issue 1: /api/targets/verify and /api/targets must not fetch internal addresses."""

from __future__ import annotations

import httpx
import pytest

import server
from backend import netguard


def _no_request(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
    raise AssertionError(f"unexpected outbound request to {request.url}")


@pytest.mark.parametrize("url", [
    "ws://169.254.169.254/x",
    "ws://[::1]/x",
    "ws://localhost/x",
    "ws://127.0.0.1:8000/ws-observe",
    "ws://2130706433/x",
    "ws://0x7f000001/x",
    "ws://127.1/x",
    "ws://[::ffff:127.0.0.1]/x",
    "ws://10.0.0.5/x",
    "ws://metadata.google.internal/x",
    "wss://foo.localhost/x",
])
def test_verify_refuses_internal_literals_without_request(client, fake_dns, http_mock, url):
    transport = http_mock(_no_request)
    resp = client.post("/api/targets/verify", json={"ws_url": url})
    body = resp.json()
    assert body["status"] == "error"
    assert body["code"] == "blocked_address"
    assert transport.requests == []
    assert fake_dns.lookups == []  # refused before DNS


def test_verify_refuses_hostname_resolving_to_private(client, fake_dns, http_mock):
    fake_dns.records["sneaky.example.com"] = ["93.184.216.34", "10.1.2.3"]
    transport = http_mock(_no_request)
    body = client.post("/api/targets/verify", json={"ws_url": "wss://sneaky.example.com/ws-observe"}).json()
    assert body["code"] == "blocked_address"
    assert "10.1.2.3" in body["message"]
    assert transport.requests == []


def test_verify_refuses_redirect_to_loopback(client, fake_dns, http_mock):
    fake_dns.records["public.example.com"] = ["93.184.216.34"]

    def handler(request):
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/ws-observe"})

    transport = http_mock(handler)
    body = client.post("/api/targets/verify", json={"ws_url": "ws://public.example.com/ws-observe"}).json()
    assert body["status"] == "error"
    assert body["code"] == "redirect_refused"
    # Exactly one request, to the checked public address; the redirect was not followed.
    assert len(transport.requests) == 1
    sent = transport.requests[0]
    assert sent.url.host == "93.184.216.34"
    assert sent.headers["host"] == "public.example.com"


@pytest.mark.parametrize("url", ["http://example.com/x", "https://example.com/x", "file:///etc/passwd",
                                 "gopher://example.com/", "ws://user:pw@example.com/x"])
def test_verify_rejects_bad_scheme_or_credentials(client, fake_dns, http_mock, url):
    transport = http_mock(_no_request)
    body = client.post("/api/targets/verify", json={"ws_url": url}).json()
    assert body["status"] == "error"
    assert body["code"] in ("invalid_scheme", "invalid_url")
    assert transport.requests == []


def test_verify_https_pins_ip_and_keeps_sni(client, fake_dns, http_mock):
    fake_dns.records["app.example.com"] = ["93.184.216.34"]
    transport = http_mock(lambda request: httpx.Response(404))
    body = client.post("/api/targets/verify", json={"ws_url": "wss://app.example.com/ws-observe"}).json()
    assert body["code"] == "guardian_tap_not_installed"
    sent = transport.requests[0]
    assert sent.url.scheme == "https" and sent.url.host == "93.184.216.34"
    assert sent.headers["host"] == "app.example.com"
    assert sent.extensions["sni_hostname"] == "app.example.com"


def test_add_target_refuses_internal_address(client, fake_dns):
    resp = client.post("/api/targets", json={"name": "meta", "ws_url": "ws://169.254.169.254/latest"},
                       headers={"X-Session-Id": "s1"})
    assert resp.status_code == 400
    assert resp.json()["code"] == "blocked_address"
    assert client.get("/api/targets", headers={"X-Session-Id": "s1"}).json()["targets"] == []


def test_verify_end_to_end_against_real_tap_when_private_allowed(client, tap_server, monkeypatch):
    """With ALLOW_PRIVATE_TARGETS on (local dev), a real guardian-tap app on
    127.0.0.1 passes both the HTTP health check and the pinned WebSocket handshake."""
    monkeypatch.setattr(server.settings, "allow_private_targets", True)
    tap, srv = tap_server()
    body = client.post("/api/targets/verify", json={"ws_url": f"ws://127.0.0.1:{srv.port}/ws-observe"}).json()
    assert body["status"] == "ok", body
    assert body["details"]["framework"] == "starlette"
    assert tap.ws_connections == 1


@pytest.mark.parametrize("host,expected", [
    ("2130706433", "127.0.0.1"), ("0x7f000001", "127.0.0.1"), ("0177.0.0.1", "127.0.0.1"),
    ("127.1", "127.0.0.1"), ("10.1", "10.0.0.1"), ("8.8.8.8", "8.8.8.8"),
])
def test_parse_ipv4_loose_forms(host, expected):
    assert str(netguard.parse_ipv4_loose(host)) == expected


@pytest.mark.parametrize("host", ["example.com", "cafe.be", "08.1.2.3", "1.2.3.4.5", "256.1.1.1"])
def test_parse_ipv4_loose_rejects_non_ips(host):
    assert netguard.parse_ipv4_loose(host) is None


@pytest.mark.parametrize("ip", ["::1", "::ffff:10.0.0.1", "2002:7f00:1::", "64:ff9b::a9fe:a9fe", "fe80::1",
                                "100.100.100.200", "100.64.0.1"])
def test_classify_ip_internal_ipv6_and_special(ip):
    import ipaddress
    assert netguard.classify_ip(ipaddress.ip_address(ip)) is not None
