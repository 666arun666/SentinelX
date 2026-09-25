from __future__ import annotations

from typer.testing import CliRunner

from sentinelx.cli.main import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "SentinelX" in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "monitor" in result.stdout
    assert "investigate" in result.stdout


def test_status_command_runs() -> None:
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "SentinelX" in result.stdout


def test_doctor_command_runs() -> None:
    result = runner.invoke(app, ["doctor"])
    # Doctor may exit 1 if infra (postgres/redis/qdrant) isn't running locally —
    # that's expected in a dev/test sandbox. It must never crash with a traceback.
    assert result.exit_code in (0, 1)
    assert "SentinelX Doctor" in result.stdout
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_config_show_masks_secrets(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-supersecretvalue")
    from sentinelx.config.settings import get_settings

    get_settings.cache_clear()
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "supersecretvalue" not in result.stdout
    get_settings.cache_clear()


def test_config_validate_runs() -> None:
    result = runner.invoke(app, ["config", "validate"])
    assert result.exit_code == 0
    assert "valid" in result.stdout.lower()


def test_monitor_stub_runs() -> None:
    result = runner.invoke(app, ["monitor"])
    assert result.exit_code == 0
    assert "not implemented yet" in result.stdout


def test_investigate_stub_runs() -> None:
    result = runner.invoke(app, ["investigate"])
    assert result.exit_code == 0
    assert "not implemented yet" in result.stdout


def test_report_stub_runs() -> None:
    result = runner.invoke(app, ["report"])
    assert result.exit_code == 0


def test_alerts_stub_runs() -> None:
    result = runner.invoke(app, ["alerts"])
    assert result.exit_code == 0
