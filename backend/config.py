import logging

from dotenv import load_dotenv
from pydantic import field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

VALID_BLOCK_THRESHOLDS = ("low", "medium", "high", "critical")


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    # Lowest severity that /api/check refuses: low, medium, high or critical.
    block_threshold: str = "high"
    # Let /api/targets and /api/targets/verify connect to loopback and private
    # addresses. Off by default because the hosted demo must never fetch
    # internal URLs on behalf of a browser; turn it on for local development.
    allow_private_targets: bool = False
    # Policy file for tool-call decisions (relative paths resolve from the repo
    # root). Reloaded on change.
    guardian_policy_file: str = ""
    # "name=key,name2=key2". When set, /api/check needs "Authorization: Bearer
    # <key>" and the caller's session and agent identity come from the key.
    guardian_api_keys: str = ""
    # Same format. Keys allowed to approve or deny pending calls. Required for
    # approvals whenever GUARDIAN_API_KEYS is set.
    guardian_approver_keys: str = ""
    # Send usage rows (connections, blocks, session starts with IP and user
    # agent) to Supabase. Off by default; also needs SUPABASE_URL and
    # SUPABASE_ANON_KEY. Traces (OTEL_EXPORTER_OTLP_ENDPOINT) are the audit path.
    guardian_usage_logging: bool = False
    # Directory of per-tenant policy files, <tenant>.yaml. A tenant's rules are
    # checked after the base policy's. The tenant is the API key name up to
    # its first dot. Empty: every caller gets the base policy.
    guardian_tenant_policies_dir: str = ""
    # Postgres connection string. When set, approvals are stored there (shared
    # by every replica, kept across restarts) and every decision and approval
    # change is appended to the audit log. Empty: approvals live in this
    # process's memory and there is no audit log.
    guardian_database_url: str = ""
    guardian_database_pool_size: int = 10
    # With a database: refuse to answer /api/check (503) when the audit row
    # cannot be written. Turning this off lets decisions go unrecorded while
    # the database is down.
    guardian_audit_required: bool = True

    @field_validator("block_threshold", mode="before")
    @classmethod
    def _normalize_block_threshold(cls, value):
        """Case-insensitive; an unknown value falls back to "high" with a warning."""
        normalized = str(value).strip().lower() if value is not None else ""
        if normalized not in VALID_BLOCK_THRESHOLDS:
            logger.warning(
                "Invalid BLOCK_THRESHOLD %r (expected one of %s); using 'high'",
                value, ", ".join(VALID_BLOCK_THRESHOLDS),
            )
            return "high"
        return normalized

    model_config = {"env_file": ".env", "extra": "ignore"}


def load_env_file(path: str = ".env") -> None:
    """Put ``.env`` entries into the process environment, without overriding
    variables that are already set.

    Settings fields read ``.env`` themselves, but several variables are read
    from ``os.environ`` directly (OTEL_*, SUPABASE_*, GUARDIAN_MODEL_DETECTORS,
    GUARDIAN_OTEL_CAPTURE_ARGUMENTS), so without this they would be ignored
    when set only in ``.env``.
    """
    load_dotenv(path, override=False)


load_env_file()
settings = Settings()
