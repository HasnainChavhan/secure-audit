"""
SecureAudit — Core Configuration
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "SecureAudit"
    app_version: str = "1.0.0"
    debug: bool = False

    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    supabase_url: str = ""
    supabase_key: str = ""

    max_retries: int = 3
    retry_delay: float = 1.0

    report_output_dir: str = "reports"

    class Config:
        env_file = ".env"


settings = Settings()
