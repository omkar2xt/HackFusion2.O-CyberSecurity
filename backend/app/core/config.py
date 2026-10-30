"""
SignalSafe Campus - Core Configuration Settings
"""

from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PROJECT_NAME: str = "SignalSafe Campus API"
    API_V1_STR: str = "/api/v1"
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # Supabase Configuration
    # Project: signalsafe-campus (xmhzqepctzkvbovurxvh, eu-west-1)
    SUPABASE_URL: str = "https://xmhzqepctzkvbovurxvh.supabase.co"
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    SUPABASE_JWT_SECRET: str = ""
    SUPABASE_JWKS_URL: str = (
        "https://xmhzqepctzkvbovurxvh.supabase.co/auth/v1/.well-known/jwks.json"
    )
    SUPABASE_JWT_AUDIENCE: str = "authenticated"
    SUPABASE_JWT_ISSUER: str = (
        "https://xmhzqepctzkvbovurxvh.supabase.co/auth/v1"
    )

    # CORS Settings
    CORS_ORIGINS: Union[str, List[str]] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]
    ALLOW_BROWSER_EXTENSIONS: bool = True

    # Detection & Threats
    SCORING_POLICY_VERSION: str = "v1.0.0"
    VIRUSTOTAL_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v  # type: ignore
        raise ValueError(v)


settings = Settings()
