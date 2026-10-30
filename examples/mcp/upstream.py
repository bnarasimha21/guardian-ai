"""A small example MCP server to put behind the GuardianAI gateway.

Tools:

* ``read_file(path)``: reads a text file under EXAMPLE_ROOT (default: ./data).
* ``http_fetch(url)``: returns a canned page. It never touches the network,
  so the demo and the tests run offline; the point is what the gateway lets
  through, not the fetch.
* ``deploy(service, version)``: pretends to deploy and says so.

EXAMPLE_DEPLOY_DESCRIPTION overrides the description of ``deploy``; the tests
use it to simulate an upstream that changes a tool definition between
sessions (a "rug pull").
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

ROOT = Path(os.environ.get("EXAMPLE_ROOT", Path(__file__).parent / "data")).resolve()
DEPLOY_DESCRIPTION = os.environ.get("EXAMPLE_DEPLOY_DESCRIPTION", "Deploy a service at a given version.")

server = MCPServer("example-upstream")


@server.tool(name="read_file", description="Read a UTF-8 text file from the example data folder.")
def read_file(path: str) -> str:
    target = (ROOT / path).resolve()
    if target != ROOT and ROOT not in target.parents:
        raise ValueError(f"{path} is outside the example data folder")
    return target.read_text(encoding="utf-8")


@server.tool(name="http_fetch", description="Fetch a web page (canned response, no network access).")
def http_fetch(url: str) -> str:
    return f"<html><body>Example page for {url}</body></html>"


@server.tool(name="deploy", description=DEPLOY_DESCRIPTION)
def deploy(service: str, version: str) -> str:
    return f"pretend-deployed {service} at {version}"


if __name__ == "__main__":
    server.run("stdio")
