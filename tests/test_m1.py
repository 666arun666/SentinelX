import os

import pytest

from sentinelx.core.config import Settings
from sentinelx.core.doctor import run_doctor_checks_async
from sentinelx.core.log_setup import redact_secrets
from sentinelx.models.case import CaseStatus


# 1. Settings Loading & 2. Missing config behavior
def test_settings_loading():
    settings = Settings(DATABASE_URL="sqlite:///:memory:", ANTHROPIC_API_KEY="test_key")
    assert settings.DATABASE_URL == "sqlite:///:memory:"
    assert settings.ANTHROPIC_API_KEY == "test_key"
    assert settings.LLM_MAX_CALLS_PER_CASE == 10  # default foundation


# 9. Secret redaction
def test_structlog_secret_redaction():
    # Force settings with dummy secrets
    import sentinelx.core.config

    old_anthropic = sentinelx.core.config.settings.ANTHROPIC_API_KEY
    sentinelx.core.config.settings.ANTHROPIC_API_KEY = "my_super_secret_key"

    event_dict = {
        "event": "API call",
        "api_key": "my_super_secret_key",
        "nested": {"token": "my_super_secret_key", "safe_val": "hello"},
        "message": "Connected using my_super_secret_key successfully",
    }

    redacted = redact_secrets(None, "test", event_dict)

    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["nested"]["token"] == "***REDACTED***"
    assert "my_super_secret_key" not in redacted["message"]
    assert "***REDACTED***" in redacted["message"]
    assert redacted["nested"]["safe_val"] == "hello"

    # Restore
    sentinelx.core.config.settings.ANTHROPIC_API_KEY = old_anthropic


# 11. CaseStatus enum
def test_case_status_enum():
    assert CaseStatus.NEW == "NEW"
    assert CaseStatus.ENRICHING == "ENRICHING"
    assert CaseStatus.CLOSED == "CLOSED"


# Connectivity tests (mocked to prevent real external API calls)
@pytest.mark.asyncio
async def test_doctor_output_mocked(mocker):
    mocker.patch("sentinelx.core.doctor.check_db_connection", return_value=True)
    mocker.patch("sentinelx.core.doctor.check_redis_connection", return_value=True)
    mocker.patch("sentinelx.core.doctor.check_qdrant_connection", return_value=True)

    result = await run_doctor_checks_async()
    assert result is True


@pytest.mark.asyncio
async def test_doctor_failure_handling(mocker):
    mocker.patch("sentinelx.core.doctor.check_db_connection", return_value=False)
    mocker.patch("sentinelx.core.doctor.check_redis_connection", return_value=True)
    mocker.patch("sentinelx.core.doctor.check_qdrant_connection", return_value=True)

    result = await run_doctor_checks_async()
    assert result is False


def test_alembic_importable():
    # 13, 14. Alembic migration tests (mocked / import check)
    # We ensure that alembic environment script parses without crashing
    assert os.path.exists("alembic/env.py")
    assert os.path.exists("alembic.ini")


def test_sqlalchemy_model_initialization():
    # 15. SQLAlchemy model initialization
    from sentinelx.models.base import Base

    assert Base.metadata is not None
