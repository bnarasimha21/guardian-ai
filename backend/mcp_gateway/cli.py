"""``guardian-mcp``: run the gateway over stdio, or manage tool pins.

    guardian-mcp --config gateway.yaml                 # serve MCP on stdin/stdout
    guardian-mcp --config gateway.yaml pins list
    guardian-mcp --config gateway.yaml pins approve files.read_file
    guardian-mcp --config gateway.yaml pins forget files.read_file

stdout carries the MCP protocol, so everything else (logs, the dashboard's
server log) goes to stderr.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import anyio

from backend.config import settings
from backend.events.bus import EventBus
from backend.guardian.middleware import Guardian
from backend.policy.loader import PolicyError, PolicyStore, resolve_policy_path

from .config import ConfigError, GatewayConfig, load_config
from .pins import PinError, PinStore
from .proxy import AuditLog, Gateway

logger = logging.getLogger("guardian-mcp")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guardian-mcp", description="GuardianAI MCP gateway")
    p.add_argument("--config", "-c", required=True, help="path to gateway.yaml")
    p.add_argument("--log-level", default="INFO", help="log level for stderr (default INFO)")
    sub = p.add_subparsers(dest="command")
    pins = sub.add_parser("pins", help="list or approve pinned tool definitions")
    pins_sub = pins.add_subparsers(dest="pins_command", required=True)
    pins_sub.add_parser("list", help="show every pin, changed ones first")
    approve = pins_sub.add_parser("approve", help="accept the changed definition of <server.tool>")
    approve.add_argument("name")
    forget = pins_sub.add_parser("forget", help="drop the pin for <server.tool> (re-pinned on next listing)")
    forget.add_argument("name")
    return p


def _pins_command(cfg: GatewayConfig, args: argparse.Namespace) -> int:
    store = PinStore(cfg.path(cfg.pins_file))
    if args.pins_command == "list":
        pins = store.all()
        if not pins:
            print("no pinned tools yet")
            return 0
        for name in sorted(pins, key=lambda n: (not pins[n].get("pending_sha256"), n)):
            pin = pins[name]
            if pin.get("pending_sha256"):
                print(f"CHANGED  {name}  pinned {pin['sha256'][:12]}  now {pin['pending_sha256'][:12]}  "
                      f"(run: guardian-mcp --config {args.config} pins approve {name})")
            else:
                print(f"ok       {name}  {pin['sha256'][:12]}")
        return 0
    if args.pins_command == "approve":
        pin = store.approve(args.name)
        print(f"approved {args.name}: now pinned to {pin['sha256'][:12]} "
              f"(was {pin.get('previous_sha256', '')[:12]})")
        return 0
    store.forget(args.name)
    print(f"forgot the pin for {args.name}")
    return 0


class _SessionRecorder:
    """Records into the dashboard's per-session Guardian (looked up each time,
    since the server may evict and recreate idle sessions)."""

    def __init__(self, server_module: Any, session: str) -> None:
        self._server = server_module
        self._session = session

    async def record(self, *args: Any, **kwargs: Any):
        return await self._server._get_session(self._session)["guardian"].record(*args, **kwargs)


@asynccontextmanager
async def _dashboard(cfg: GatewayConfig, policy_path) -> AsyncIterator[Any]:
    """Run the GuardianAI web app in this process, so gateway decisions and
    approvals show on its dashboard and can be answered there."""
    import uvicorn

    import server as web  # the FastAPI app (top-level server.py)

    settings.guardian_policy_file = str(policy_path)
    sock = socket.socket(socket.AF_INET6 if ":" in cfg.dashboard.host else socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((cfg.dashboard.host, cfg.dashboard.port))
    except OSError as exc:
        sock.close()
        raise ConfigError(f"dashboard cannot listen on {cfg.dashboard.host}:{cfg.dashboard.port}: {exc}") from exc
    sock.listen(128)
    sock.setblocking(False)
    port = sock.getsockname()[1]
    uv = uvicorn.Server(uvicorn.Config(web.app, log_config=None, access_log=False, lifespan="on"))
    async with anyio.create_task_group() as tg:
        tg.start_soon(uv.serve, [sock])
        with anyio.fail_after(30):
            while not uv.started:
                if uv.should_exit:
                    raise ConfigError("the dashboard server failed to start")
                await anyio.sleep(0.05)
        try:
            yield web, port
        finally:
            uv.should_exit = True
    sock.close()


def _policy_path(cfg: GatewayConfig):
    return cfg.path(cfg.policy_file) if cfg.policy_file else resolve_policy_path(settings.guardian_policy_file)


async def serve(cfg: GatewayConfig, *, log_level: str = "INFO") -> None:
    import mcp.server.stdio

    policy_path = _policy_path(cfg)
    policy_store = PolicyStore(policy_path)
    policy_store.get()
    pins = PinStore(cfg.path(cfg.pins_file))
    audit = AuditLog(cfg.path(cfg.audit_log)) if cfg.audit_log else None

    async def run(gateway: Gateway) -> None:
        async with gateway:
            async with mcp.server.stdio.stdio_server() as (read, write):
                await gateway.server.run(read, write, gateway.server.create_initialization_options())

    if not cfg.dashboard.enabled:
        gateway = Gateway(cfg, recorder=Guardian(event_bus=EventBus()), policy_store=policy_store, pins=pins,
                          session=cfg.dashboard.session, block_threshold=settings.block_threshold, audit=audit)
        await run(gateway)
        return

    async with _dashboard(cfg, policy_path) as (web, port):
        host = cfg.dashboard.host
        shown = f"[{host}]" if ":" in host else host
        url = f"http://{shown}:{port}/?session={cfg.dashboard.session}"
        logger.info("dashboard for this gateway: %s", url)
        gateway = Gateway(cfg, recorder=_SessionRecorder(web, cfg.dashboard.session),
                          policy_store=web._policy_store(), pins=pins, approvals=web._approvals(),
                          session=cfg.dashboard.session, block_threshold=settings.block_threshold, audit=audit,
                          dashboard_url=url)
        await run(gateway)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=getattr(logging, str(args.log_level).upper(), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", force=True)
    try:
        cfg = load_config(args.config)
        if args.command == "pins":
            return _pins_command(cfg, args)
        PolicyStore(_policy_path(cfg)).get()  # refuse to start on a broken policy
        anyio.run(serve, cfg)
    except (ConfigError, PolicyError, PinError) as exc:
        print(f"guardian-mcp: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
