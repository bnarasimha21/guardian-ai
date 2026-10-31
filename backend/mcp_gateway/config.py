"""gateway.yaml: which upstream MCP servers to front, and how.

Example::

    servers:
      files:                       # namespace: tools appear as files.<tool>
        command: python
        args: [examples/mcp/upstream.py]
        env: {EXAMPLE_ROOT: examples/mcp/data}
      remote:
        url: http://127.0.0.1:9000/mcp
        headers: {Authorization: "Bearer ${REMOTE_TOKEN}"}

    agent: claude-desktop          # who the policy's `agent:` matches
    policy_file: policies/default.yaml
    pins_file: .guardian/mcp-pins.json
    audit_log: .guardian/mcp-audit.jsonl
    separator: "."
    elicitation: true
    dashboard: {enabled: false, host: 127.0.0.1, port: 8000, session: mcp-gateway}

Relative `cwd`, `policy_file`, `pins_file` and `audit_log` paths are
resolved against the directory that holds the config file, and a stdio
upstream with no `cwd` runs in that directory, so relative script paths in
`args` work from anywhere. `${VAR}` in `env` and `headers` values is read from the
gateway's own environment, so secrets stay out of the file.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_NAMESPACE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UpstreamConfig(_Strict):
    command: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: Optional[str] = None
    url: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _one_transport(self) -> "UpstreamConfig":
        if bool(self.command) == bool(self.url):
            raise ValueError("each server needs exactly one of 'command' (stdio) or 'url' (Streamable HTTP)")
        return self


class DashboardConfig(_Strict):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8000
    session: str = "mcp-gateway"

    @field_validator("session")
    @classmethod
    def _session(cls, v: str) -> str:
        if not v or v.startswith("app:") or len(v) > 200:
            raise ValueError("dashboard.session must be 1-200 characters and must not start with 'app:'")
        return v


class GatewayConfig(_Strict):
    servers: dict[str, UpstreamConfig]
    agent: str = "mcp-client"
    policy_file: Optional[str] = None
    pins_file: str = ".guardian/mcp-pins.json"
    audit_log: Optional[str] = None
    separator: str = "."
    elicitation: bool = True
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    base_dir: str = ""

    @field_validator("servers")
    @classmethod
    def _names(cls, v: dict[str, UpstreamConfig]) -> dict[str, UpstreamConfig]:
        if not v:
            raise ValueError("configure at least one server")
        for name in v:
            if not _NAMESPACE.match(name):
                raise ValueError(f"server name {name!r} must match [A-Za-z0-9_-]{{1,64}}")
        return v

    @field_validator("separator")
    @classmethod
    def _sep(cls, v: str) -> str:
        if not v or not re.fullmatch(r"[._\-]{1,3}", v):
            raise ValueError("separator must be 1-3 of the characters . _ -")
        return v

    def path(self, value: str | None) -> Path | None:
        if not value:
            return None
        p = Path(value).expanduser()
        return p if p.is_absolute() else Path(self.base_dir) / p


def _expand(value: str, where: str) -> str:
    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name not in os.environ:
            raise ConfigError(f"{where} refers to ${{{name}}}, which is not set in the environment")
        return os.environ[name]
    return _ENV_REF.sub(sub, value)


def load_config(path: str | os.PathLike) -> GatewayConfig:
    p = Path(path).expanduser().resolve()
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {p}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{p} must be a mapping with a 'servers' key")
    raw = {**raw, "base_dir": str(p.parent)}
    try:
        cfg = GatewayConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{p}: {exc}") from exc
    for name, up in cfg.servers.items():
        up.env = {k: _expand(v, f"servers.{name}.env.{k}") for k, v in up.env.items()}
        up.headers = {k: _expand(v, f"servers.{name}.headers.{k}") for k, v in up.headers.items()}
        if up.command:
            up.cwd = str(cfg.path(up.cwd)) if up.cwd else cfg.base_dir
    return cfg
