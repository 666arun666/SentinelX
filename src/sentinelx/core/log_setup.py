import logging
from typing import Any

import structlog

from sentinelx.core.config import settings


def redact_secrets(
    logger: logging.Logger, name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Redact sensitive values from log output."""
    sensitive_keys = {"api_key", "password", "token", "secret", "authorization"}

    # Collect actual secret values to redact if they appear anywhere
    secret_values = []
    if settings.ANTHROPIC_API_KEY:
        secret_values.append(settings.ANTHROPIC_API_KEY)
    if settings.VIRUSTOTAL_API_KEY:
        secret_values.append(settings.VIRUSTOTAL_API_KEY)
    if settings.ABUSEIPDB_API_KEY:
        secret_values.append(settings.ABUSEIPDB_API_KEY)
    if settings.OPENCTI_API_KEY:
        secret_values.append(settings.OPENCTI_API_KEY)

    # Extract password from DATABASE_URL if present
    # format: postgresql+psycopg://user:password@host...
    db_url = settings.DATABASE_URL
    if "@" in db_url and ":" in db_url:
        try:
            pwd_part = db_url.split("@")[0].split(":")[-1]
            if pwd_part and pwd_part != "postgresql+psycopg" and pwd_part != "redis":
                secret_values.append(pwd_part)
        except (ValueError, AttributeError):
            pass

    def _redact(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: (
                    _redact(v)
                    if not any(sk in k.lower() for sk in sensitive_keys)
                    else "***REDACTED***"
                )
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [_redact(i) for i in obj]
        elif isinstance(obj, str):
            res = obj
            for sv in secret_values:
                if sv and len(sv) > 3:  # Avoid redacting short accidental matches
                    res = res.replace(sv, "***REDACTED***")
            return res
        return obj

    return _redact(event_dict)


def configure_logging():
    """Configure structlog."""
    structlog.configure(
        processors=[
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            redact_secrets,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
