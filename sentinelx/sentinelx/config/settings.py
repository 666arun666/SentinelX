"""Central application configuration.

All configuration is environment-driven (12-factor style). Nothing here
should ever contain a real secret - only field definitions and safe
defaults. See ``.env.example`` for the full list of supported variables.

Optional integrations (LLM providers, threat intel APIs, LangSmith, OpenCTI)
are all allowed to be unset. Code that depends on them must check the
corresponding ``is_configured`` helper and degrade gracefully instead of
raising at import time.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core application ---------------------------------------------
    app_name: str = "SentinelX"
    environment: str = Field(default="development", description="development|staging|production")
    log_level: str = Field(default="INFO")
    data_dir: Path = Field(default=Path("./data"))
    reports_dir: Path = Field(default=Path("./data/reports"))
    demo_mode: bool = Field(default=False, description="Force use of mock/demo providers")

    # --- Database --------------------------------------------------------
    database_url: str = Field(
        default="postgresql+psycopg2://sentinelx:sentinelx@localhost:5432/sentinelx",
        description="SQLAlchemy-style PostgreSQL connection string",
    )

    # --- Redis -------------------------------------------------------------
    redis_url: str = Field(default="redis://localhost:6379/0")

    # --- Vector store (RAG) ------------------------------------------------
    qdrant_url: str = Field(default="http://localhost:6333")
    qdrant_collection_mitre: str = Field(default="sentinelx_mitre")
    qdrant_collection_sigma: str = Field(default="sentinelx_sigma")
    qdrant_collection_cases: str = Field(default="sentinelx_cases")

    # --- LLM -----------------------------------------------------------
    anthropic_api_key: str | None = Field(default=None)
    llm_model_reasoning: str = Field(
        default="claude-sonnet-4-6", description="Higher-tier model for reasoning-heavy agents"
    )
    llm_model_fast: str = Field(
        default="claude-haiku-4-5", description="Lower-tier model for cheap/simple tasks"
    )

    # --- Observability ---------------------------------------------------
    langsmith_api_key: str | None = Field(default=None)
    langsmith_project: str = Field(default="sentinelx")
    langsmith_tracing: bool = Field(default=False)

    # --- Threat intelligence ---------------------------------------------
    virustotal_api_key: str | None = Field(default=None)
    abuseipdb_api_key: str | None = Field(default=None)
    opencti_url: str | None = Field(default=None)
    opencti_api_key: str | None = Field(default=None)

    # --- Log sources (Linux host monitoring) ------------------------------
    monitor_auth_log: Path = Field(default=Path("/var/log/auth.log"))
    monitor_syslog: Path = Field(default=Path("/var/log/syslog"))
    monitor_use_journalctl: bool = Field(default=True)
    monitor_use_auditd: bool = Field(default=False)
    monitor_hostname: str | None = Field(default=None)

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}, got {v!r}")
        return upper

    # --- Convenience helpers -----------------------------------------------
    @property
    def llm_configured(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def langsmith_configured(self) -> bool:
        return bool(self.langsmith_api_key) and self.langsmith_tracing

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def abuseipdb_configured(self) -> bool:
        return bool(self.abuseipdb_api_key)

    @property
    def opencti_configured(self) -> bool:
        return bool(self.opencti_url and self.opencti_api_key)

    def ensure_directories(self) -> None:
        """Create local data/report directories if they don't exist yet."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (singleton for the process)."""
    return Settings()
