from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinelx.config.settings import Settings, get_settings


def test_settings_load_with_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.app_name == "SentinelX"
    assert settings.environment == "development"
    assert settings.llm_configured is False


def test_settings_optional_integrations_default_unconfigured() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.virustotal_configured is False
    assert settings.abuseipdb_configured is False
    assert settings.opencti_configured is False
    assert settings.langsmith_configured is False


def test_settings_llm_configured_when_key_present() -> None:
    settings = Settings(_env_file=None, anthropic_api_key="sk-test-123")  # type: ignore[call-arg]
    assert settings.llm_configured is True


def test_settings_rejects_invalid_log_level() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, log_level="NOT_A_LEVEL")  # type: ignore[call-arg]


def test_get_settings_is_cached() -> None:
    a = get_settings()
    b = get_settings()
    assert a is b


def test_ensure_directories_creates_paths(tmp_path) -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "data" / "reports",
    )
    settings.ensure_directories()
    assert settings.data_dir.exists()
    assert settings.reports_dir.exists()
