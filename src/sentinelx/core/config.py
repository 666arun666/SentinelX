from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Infrastructure
    DATABASE_URL: str = (
        "postgresql+psycopg://sentinelx:password@localhost:5432/sentinelx"
    )
    REDIS_URL: str = "redis://localhost:6379/0"
    QDRANT_URL: str = "http://localhost:6333"

    # API Keys
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OPENCTI_URL: str = ""
    OPENCTI_API_KEY: str = ""

    # Foundations
    RISK_SCORE_WEIGHTS: str = '{"criticality": 0.4, "severity": 0.6}'
    RISK_AI_ADJUSTMENT_BOUND: int = 20
    CORRELATION_WINDOW_SECONDS: int = 3600
    CORRELATION_SIMILARITY_THRESHOLD: float = 0.75
    QDRANT_COLLECTION_NAME: str = "findings"
    BACKPRESSURE_QUEUE_SIZE: int = 1000
    DETECTION_QUEUE_SIZE: int = 1000

    LLM_MODEL_TIER_1: str = "claude-3-haiku-20240307"
    LLM_MODEL_TIER_2: str = "claude-3-sonnet-20240229"
    LLM_MODEL_TIER_3: str = "claude-3-opus-20240229"

    LLM_MAX_CALLS_PER_CASE: int = 10
    LLM_MAX_COST_PER_CASE: float = 0.50
    LLM_MAX_COST_PER_DAY: float = 5.0

    RETENTION_PERIOD_DAYS: int = 30
    DISK_SPACE_WARNING_THRESHOLD: float = 0.85

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()
