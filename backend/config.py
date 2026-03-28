from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # LLM (kept for gradient-adk deployment)
    gradient_model_access_key: str = ""
    model_name: str = "llama3.3-70b-instruct"
    inference_base_url: str = "https://inference.do-ai.run/v1"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
