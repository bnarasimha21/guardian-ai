import logging

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


settings = Settings()
