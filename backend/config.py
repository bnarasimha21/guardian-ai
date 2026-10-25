from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    # Lowest severity that /api/check refuses: low, medium, high or critical.
    block_threshold: str = "high"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
