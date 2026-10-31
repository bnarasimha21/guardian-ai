"""GuardianAI as an MCP gateway: policy enforcement in front of upstream MCP servers.

Run it with ``guardian-mcp --config gateway.yaml`` (or
``python -m backend.mcp_gateway --config gateway.yaml``) and point an MCP
client at it over stdio. See ``proxy.py`` for what happens on each request.
"""

from .config import ConfigError, GatewayConfig, UpstreamConfig, load_config
from .pins import PinError, PinStore, definition_sha256
from .proxy import AuditLog, Gateway

__all__ = [
    "AuditLog", "ConfigError", "Gateway", "GatewayConfig", "PinError", "PinStore", "UpstreamConfig",
    "definition_sha256", "load_config",
]
