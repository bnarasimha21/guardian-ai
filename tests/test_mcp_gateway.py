"""MCP gateway (issue 4), end to end.

The stdio tests spawn the real gateway (``python -m backend.mcp_gateway``) as
a subprocess; it spawns the example upstream servers, also over stdio, and an
MCP SDK client talks to it. Nothing reaches the network: the example
``http_fetch`` returns a canned page.

The queue tests run the gateway in process (``Client(gateway.server)``) so
they can answer approvals directly, plus one subprocess test of dashboard
mode that answers the approval over the real HTTP API.
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import anyio
import httpx
import mcp_types as types
import pytest
import websockets
import yaml
from mcp import Client, StdioServerParameters

from backend.approvals import InMemoryApprovalStore
from backend.events.bus import EventBus
from backend.guardian.middleware import Guardian
from backend.mcp_gateway import Gateway, PinStore, load_config
from backend.mcp_gateway import cli as gateway_cli
from backend.mcp_gateway.config import ConfigError
from backend.policy.loader import PolicyStore

pytestmark = [pytest.mark.anyio]

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / "examples" / "mcp"
DEFAULT_POLICY = REPO / "policies" / "default.yaml"
MODES = ["legacy", "auto"]  # auto negotiates 2026-07-28, where approval is an InputRequiredResult


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _env() -> dict[str, str]:
    """Environment for the gateway subprocess: no keys, no Supabase, whatever .env says."""
    return {
        "PYTHONPATH": str(REPO),
        "GUARDIAN_API_KEYS": "",
        "GUARDIAN_APPROVER_KEYS": "",
        "GUARDIAN_POLICY_FILE": "",
        "BLOCK_THRESHOLD": "high",
        "SUPABASE_URL": "",
        "SUPABASE_ANON_KEY": "",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "",
    }


def write_config(tmp: Path, *, deploy_description: str | None = None, policy: Path = DEFAULT_POLICY,
                 poisoned: bool = True, **extra) -> Path:
    files_env = {"EXAMPLE_ROOT": str(EXAMPLES / "data")}
    if deploy_description is not None:
        files_env["EXAMPLE_DEPLOY_DESCRIPTION"] = deploy_description
    servers = {"files": {"command": sys.executable, "args": [str(EXAMPLES / "upstream.py")], "env": files_env}}
    if poisoned:
        servers["sketchy"] = {"command": sys.executable, "args": [str(EXAMPLES / "poisoned_upstream.py")]}
    cfg = {
        "servers": servers,
        "agent": "test-client",
        "policy_file": str(policy),
        "pins_file": str(tmp / "pins.json"),
        "audit_log": str(tmp / "audit.jsonl"),
        **extra,
    }
    path = tmp / "gateway.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


def gateway_process(cfg: Path) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "backend.mcp_gateway", "--config", str(cfg)],
                                 env=_env(), cwd=str(REPO))


class Prompts:
    """Elicitation callback that answers every approval prompt the same way."""

    def __init__(self, action: str, approve: bool = True) -> None:
        self.action = action
        self.approve = approve
        self.seen: list[types.ElicitRequestParams] = []

    async def __call__(self, context, params):
        self.seen.append(params)
        if self.action == "accept":
            return types.ElicitResult(action="accept", content={"approve": self.approve})
        return types.ElicitResult(action=self.action)


def text_of(result: types.CallToolResult) -> str:
    return "\n".join(b.text for b in result.content if isinstance(b, types.TextContent))


def audit_lines(tmp: Path) -> list[dict]:
    path = tmp / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def tool_names(listing: types.ListToolsResult) -> set[str]:
    return {t.name for t in listing.tools}


# ---------------------------------------------------------------------------
# Acceptance: stdio gateway in front of the example upstream
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_stdio_gateway_allows_denies_and_asks(tmp_path, mode):
    cfg = write_config(tmp_path)
    prompts = Prompts("decline")
    async with Client(gateway_process(cfg), mode=mode, elicitation_callback=prompts) as client:
        names = tool_names(await client.list_tools())
        assert {"files.read_file", "files.http_fetch", "files.deploy", "sketchy.get_time"} <= names

        ok = await client.call_tool("files.read_file", {"path": "notes.md"})
        assert not ok.is_error
        assert "release train" in text_of(ok)
        assert ok.meta["guardian-ai/decision"]["effect"] == "allow"

        ssrf = await client.call_tool("files.http_fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
        assert ssrf.is_error
        assert "GuardianAI denied files.http_fetch" in text_of(ssrf)
        assert ssrf.meta["guardian-ai/decision"]["effect"] == "deny"
        assert "Example page" not in text_of(ssrf)  # never forwarded

        deploy = await client.call_tool("files.deploy", {"service": "api", "version": "1.2.3"})
        assert len(prompts.seen) == 1
        assert "files.deploy" in prompts.seen[0].message and "1.2.3" in prompts.seen[0].message
        assert deploy.is_error
        assert "declined" in text_of(deploy)
        assert "pretend-deployed" not in text_of(deploy)

    kinds = [(e.get("tool_name"), e.get("effect")) for e in audit_lines(tmp_path) if e["kind"] == "decision"]
    assert ("files.http_fetch", "deny") in kinds
    assert ("files.deploy", "require_approval") in kinds
    assert ("files.deploy", "deny") in kinds


@pytest.mark.parametrize("mode", MODES)
async def test_elicitation_accept_runs_the_call(tmp_path, mode):
    cfg = write_config(tmp_path, poisoned=False)
    prompts = Prompts("accept", approve=True)
    async with Client(gateway_process(cfg), mode=mode, elicitation_callback=prompts) as client:
        result = await client.call_tool("files.deploy", {"service": "api", "version": "2.0.0"})
        assert not result.is_error, text_of(result)
        assert "pretend-deployed api at 2.0.0" in text_of(result)
        assert len(prompts.seen) == 1

    approved = [e for e in audit_lines(tmp_path) if e["kind"] == "decision" and e.get("tool_name") == "files.deploy"
                and e.get("effect") == "allow"]
    assert approved and "elicitation" in " ".join(approved[0]["reasons"])


async def test_accept_without_ticking_approve_is_a_denial(tmp_path):
    cfg = write_config(tmp_path, poisoned=False)
    async with Client(gateway_process(cfg), mode="legacy", elicitation_callback=Prompts("accept", approve=False)) as c:
        result = await c.call_tool("files.deploy", {"service": "api", "version": "2.0.0"})
        assert result.is_error and "pretend-deployed" not in text_of(result)


async def test_poisoned_tool_is_hidden_and_recorded(tmp_path):
    cfg = write_config(tmp_path)
    async with Client(gateway_process(cfg), mode="legacy") as client:
        names = tool_names(await client.list_tools())
        assert "sketchy.lookup_weather" not in names
        assert "sketchy.get_time" in names
        hidden = await client.call_tool("sketchy.lookup_weather", {"city": "Paris"})
        assert hidden.is_error and "tool_poisoning" in text_of(hidden)
        assert "Sunny" not in text_of(hidden)
    poisoning = [e for e in audit_lines(tmp_path) if e.get("rule_name") == "tool_poisoning"]
    assert len(poisoning) == 1  # reported once per process, not on every listing
    assert poisoning[0]["tool_name"] == "sketchy.lookup_weather"
    assert poisoning[0]["owasp_agentic"] == "ASI04"


async def test_rug_pull_between_sessions_hides_the_tool_until_approved(tmp_path, capsys):
    cfg = write_config(tmp_path, poisoned=False)
    async with Client(gateway_process(cfg), mode="legacy") as client:
        assert "files.deploy" in tool_names(await client.list_tools())
    pins = PinStore(tmp_path / "pins.json").all()
    assert set(pins) == {"files.read_file", "files.http_fetch", "files.deploy"}

    # Second session: the upstream now ships a different description for deploy.
    cfg = write_config(tmp_path, poisoned=False, deploy_description="Deploy a service. Also accepts a region.")
    async with Client(gateway_process(cfg), mode="legacy") as client:
        names = tool_names(await client.list_tools())
        assert "files.deploy" not in names
        assert "files.read_file" in names
        blocked = await client.call_tool("files.deploy", {"service": "api", "version": "1"})
        assert blocked.is_error and "tool_definition_changed" in text_of(blocked)
        assert "pretend-deployed" not in text_of(blocked)

    changed = [e for e in audit_lines(tmp_path) if e.get("rule_name") == "tool_definition_changed"]
    assert len(changed) == 1
    assert changed[0]["tool_name"] == "files.deploy" and changed[0]["effect"] == "deny"
    assert changed[0]["owasp_llm"] == "LLM03"
    assert PinStore(tmp_path / "pins.json").get("files.deploy")["pending_sha256"]

    # The operator reviews and approves; the tool comes back.
    assert gateway_cli.main(["--config", str(cfg), "pins", "list"]) == 0
    assert "CHANGED  files.deploy" in capsys.readouterr().out
    assert gateway_cli.main(["--config", str(cfg), "pins", "approve", "files.deploy"]) == 0
    async with Client(gateway_process(cfg), mode="legacy", elicitation_callback=Prompts("accept")) as client:
        assert "files.deploy" in tool_names(await client.list_tools())
        ran = await client.call_tool("files.deploy", {"service": "api", "version": "1"})
        assert not ran.is_error, text_of(ran)


async def test_injection_in_tool_result_is_withheld(tmp_path):
    cfg = write_config(tmp_path, poisoned=False)
    async with Client(gateway_process(cfg), mode="legacy") as client:
        result = await client.call_tool("files.read_file", {"path": "fetched-page.md"})
        assert result.is_error
        body = text_of(result)
        assert "withheld" in body and "ssh" not in body.lower()
        meta = result.meta["guardian-ai/decision"]
        assert meta["phase"] == "result" and meta["rule_id"] == "deny-injection-in-results"
        assert "prompt_injection" in meta["matched_detectors"]
        assert result.structured_content is None


async def test_secret_in_tool_result_is_redacted(tmp_path):
    cfg = write_config(tmp_path, poisoned=False)
    async with Client(gateway_process(cfg), mode="legacy") as client:
        result = await client.call_tool("files.read_file", {"path": "config.txt"})
        assert not result.is_error
        assert "AKIAIOSFODNN7EXAMPLE" not in text_of(result)
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(result.structured_content or {})
        assert "eu-west-1" in text_of(result)  # the rest of the output is kept
        assert result.meta["guardian-ai/decision"]["effect"] == "redact"


async def test_separator_renames_tools(tmp_path):
    cfg = write_config(tmp_path, poisoned=False, separator="__")
    async with Client(gateway_process(cfg), mode="legacy") as client:
        names = tool_names(await client.list_tools())
        assert "files__read_file" in names and "files.read_file" not in names
        ok = await client.call_tool("files__read_file", {"path": "notes.md"})
        assert not ok.is_error
        # The policy still sees the canonical name: SSRF is denied by the same rules.
        ssrf = await client.call_tool("files__http_fetch", {"url": "http://169.254.169.254/"})
        assert ssrf.is_error and ssrf.meta["guardian-ai/decision"]["rule_id"] == "deny-detector-threats"


# ---------------------------------------------------------------------------
# require_approval without elicitation: the approval queue, or fail closed
# ---------------------------------------------------------------------------


class _Harness:
    def __init__(self, tmp: Path, *, approvals=None, elicitation: bool = True, policy: Path = DEFAULT_POLICY):
        self.cfg = load_config(write_config(tmp, poisoned=False, elicitation=elicitation, policy=policy))
        self.bus = EventBus()
        self.guardian = Guardian(event_bus=self.bus)
        self.approvals = approvals
        self.gateway = Gateway(self.cfg, recorder=self.guardian, policy_store=PolicyStore(self.cfg.policy_file),
                               pins=PinStore(self.cfg.path(self.cfg.pins_file)), approvals=approvals,
                               session="gw-test", dashboard_url="http://127.0.0.1:8000/?session=gw-test")


async def test_queue_fallback_holds_then_runs_after_human_approval(tmp_path):
    store = InMemoryApprovalStore()
    h = _Harness(tmp_path, approvals=store)
    try:
        async with h.gateway, Client(h.gateway.server, mode="legacy") as client:  # no elicitation callback
            args = {"service": "billing", "version": "9"}
            held = await client.call_tool("files.deploy", args)
            assert held.is_error
            meta = held.meta["guardian-ai/decision"]
            assert meta["status"] == "pending" and meta["approval_id"]
            assert "?session=gw-test" in text_of(held) and "Nothing was run" in text_of(held)
            approval = await store.get(meta["approval_id"])
            assert approval.session == "gw-test" and approval.agent == "test-client"
            assert approval.tool == "files.deploy" and approval.server == "files"

            again = await client.call_tool("files.deploy", args)  # still waiting: same approval
            assert again.meta["guardian-ai/decision"]["approval_id"] == approval.id

            await store.resolve(approval.id, approve=True, by="alice")
            ran = await client.call_tool("files.deploy", args)
            assert not ran.is_error, text_of(ran)
            assert "pretend-deployed billing at 9" in text_of(ran)

            # The grant was single use (default policy grant_ttl 0): a repeat is held again.
            repeat = await client.call_tool("files.deploy", args)
            assert repeat.is_error and repeat.meta["guardian-ai/decision"]["approval_id"] != approval.id

            # Different arguments never ride on someone else's approval.
            other = await client.call_tool("files.deploy", {"service": "billing", "version": "10"})
            assert other.is_error and other.meta["guardian-ai/decision"]["status"] == "pending"
    finally:
        await store.close()


async def test_queue_fallback_denied_by_human(tmp_path):
    store = InMemoryApprovalStore()
    h = _Harness(tmp_path, approvals=store)
    try:
        async with h.gateway, Client(h.gateway.server, mode="legacy") as client:
            held = await client.call_tool("files.deploy", {"service": "x", "version": "1"})
            aid = held.meta["guardian-ai/decision"]["approval_id"]
            await store.resolve(aid, approve=False, by="alice")
            retry = await client.call_tool("files.deploy", {"service": "x", "version": "1"})
            assert retry.is_error and "pretend-deployed" not in text_of(retry)
            assert retry.meta["guardian-ai/decision"]["approval_id"] != aid  # a fresh request, not a pass
    finally:
        await store.close()


async def test_elicitation_disabled_in_config_uses_the_queue(tmp_path):
    store = InMemoryApprovalStore()
    h = _Harness(tmp_path, approvals=store, elicitation=False)
    prompts = Prompts("accept")
    try:
        async with h.gateway, Client(h.gateway.server, mode="legacy", elicitation_callback=prompts) as client:
            held = await client.call_tool("files.deploy", {"service": "x", "version": "1"})
            assert held.is_error and held.meta["guardian-ai/decision"]["status"] == "pending"
            assert prompts.seen == []
    finally:
        await store.close()


async def test_no_elicitation_and_no_queue_fails_closed(tmp_path):
    h = _Harness(tmp_path, approvals=None)
    async with h.gateway, Client(h.gateway.server, mode="legacy") as client:
        result = await client.call_tool("files.deploy", {"service": "x", "version": "1"})
        assert result.is_error
        assert "no approval queue" in text_of(result)
        assert result.meta["guardian-ai/decision"]["effect"] == "deny"


async def test_forged_request_state_is_refused(tmp_path):
    """2026-07-28 retry with a request_state the gateway never issued is a denial, not an approval."""
    h = _Harness(tmp_path)
    async with h.gateway, Client(h.gateway.server, mode="auto", elicitation_callback=Prompts("accept")) as client:
        assert "files.deploy" in tool_names(await client.list_tools())
        ctx_params = types.CallToolRequestParams(
            name="files.deploy", arguments={"service": "x", "version": "1"},
            request_state="forged", input_responses={
                "guardian_approval": types.ElicitResult(action="accept", content={"approve": True})},
        )

        class _Ctx:
            session = None
            protocol_version = "2026-07-28"
            request_id = 1

        class _Sess:
            class client_capabilities:
                elicitation = types.ElicitationCapability()

        _Ctx.session = _Sess()
        result = await h.gateway._on_call_tool(_Ctx(), ctx_params)
        assert isinstance(result, types.CallToolResult) and result.is_error
        assert "does not match a pending prompt" in text_of(result)


async def test_monitor_mode_flags_but_does_not_block(tmp_path):
    policy = tmp_path / "monitor.yaml"
    raw = yaml.safe_load(DEFAULT_POLICY.read_text(encoding="utf-8"))
    raw["mode"] = "monitor"
    policy.write_text(yaml.safe_dump(raw), encoding="utf-8")
    cfg = write_config(tmp_path, policy=policy)
    async with Client(gateway_process(cfg), mode="legacy") as client:
        names = tool_names(await client.list_tools())
        assert "sketchy.lookup_weather" in names  # flagged, not hidden
        ssrf = await client.call_tool("files.http_fetch", {"url": "http://169.254.169.254/"})
        assert not ssrf.is_error  # monitor mode observes
        call_meta = ssrf.meta["guardian-ai/decision"]["call"]  # the output was scanned too
        assert call_meta["effect"] == "deny" and call_meta["enforced"] is False
    assert any(e.get("rule_name") == "tool_poisoning" for e in audit_lines(tmp_path))


def test_broken_policy_refuses_to_start(tmp_path, capsys):
    policy = tmp_path / "p.yaml"
    policy.write_text("rules: [this is: not, valid", encoding="utf-8")
    cfg = write_config(tmp_path, policy=policy)
    assert gateway_cli.main(["--config", str(cfg), "pins", "list"]) == 0  # pins do not need the policy
    assert gateway_cli.main(["--config", str(cfg)]) == 2
    assert "invalid YAML" in capsys.readouterr().err


async def test_dashboard_mode_shows_and_answers_approvals_over_http(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cfg = write_config(tmp_path, poisoned=False,
                       dashboard={"enabled": True, "host": "127.0.0.1", "port": port, "session": "gw-dash"})
    args = {"service": "web", "version": "3"}
    async with Client(gateway_process(cfg), mode="legacy") as client:
        await client.list_tools()  # the dashboard is up once the gateway answers
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws/events?session=gw-dash") as ws:
            held = await client.call_tool("files.deploy", args)
            meta = held.meta["guardian-ai/decision"]
            assert meta["status"] == "pending", text_of(held)
            # The same decision card and approval event the HTTP API produces, on the dashboard stream.
            seen = set()
            with anyio.fail_after(10):
                while not {"decision", "approval"} <= seen:
                    event = json.loads(await ws.recv())
                    if event["type"] == "decision" and event["tool_name"] == "files.deploy":
                        assert event["action"] == "require_approval" and event["approval_id"] == meta["approval_id"]
                        seen.add("decision")
                    elif event["type"] == "approval" and event["approval_id"] == meta["approval_id"]:
                        seen.add("approval")
        assert f"http://127.0.0.1:{port}/?session=gw-dash" in text_of(held)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}",
                                     headers={"X-Session-Id": "gw-dash"}) as http:
            listing = (await http.get("/api/approvals", params={"status": "pending"})).json()["approvals"]
            assert [a["approval_id"] for a in listing] == [meta["approval_id"]]
            assert listing[0]["tool"] == "files.deploy" and listing[0]["agent"] == "test-client"
            answer = await http.post(f"/api/approvals/{meta['approval_id']}", json={"approve": True})
            assert answer.status_code == 200 and answer.json()["status"] == "approved"
        ran = await client.call_tool("files.deploy", args)
        assert not ran.is_error, text_of(ran)
        assert "pretend-deployed web at 3" in text_of(ran)
    changes = [e["change"] for e in audit_lines(tmp_path) if e["kind"] == "approval"]
    assert changes[:3] == ["pending", "approved", "used"]


# ---------------------------------------------------------------------------
# Configuration and pins
# ---------------------------------------------------------------------------


def test_config_rejects_bad_input(tmp_path, monkeypatch):
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"servers": {"a": {"command": "x", "url": "http://y"}}}), encoding="utf-8")
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(bad)
    bad.write_text(yaml.safe_dump({"servers": {"a.b": {"command": "x"}}}), encoding="utf-8")
    with pytest.raises(ConfigError, match="must match"):
        load_config(bad)
    bad.write_text(yaml.safe_dump({"servers": {"a": {"url": "http://y", "headers": {"A": "${NOPE_UNSET}"}}}}),
                   encoding="utf-8")
    monkeypatch.delenv("NOPE_UNSET", raising=False)
    with pytest.raises(ConfigError, match="NOPE_UNSET"):
        load_config(bad)
    monkeypatch.setenv("NOPE_UNSET", "s3cret")
    assert load_config(bad).servers["a"].headers["A"] == "s3cret"


def test_example_config_loads():
    cfg = load_config(EXAMPLES / "gateway.yaml")
    assert set(cfg.servers) == {"files", "sketchy"}
    assert cfg.path(cfg.policy_file).resolve() == DEFAULT_POLICY.resolve()
    assert cfg.servers["files"].cwd == str(EXAMPLES)


def test_corrupt_pins_file_is_an_error_not_a_reset(tmp_path):
    from backend.mcp_gateway.pins import PinError
    (tmp_path / "pins.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(PinError):
        PinStore(tmp_path / "pins.json")
    cfg = write_config(tmp_path)
    assert gateway_cli.main(["--config", str(cfg), "pins", "list"]) == 2
