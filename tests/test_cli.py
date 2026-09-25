from unittest.mock import patch

from typer.testing import CliRunner

from sentinelx.cli.main import app

runner = CliRunner()


def test_monitor_mocked_db_failure():
    """Test monitor CLI when DB fails to connect."""
    with patch("sentinelx.cli.main.check_db_connection", return_value=False):
        result = runner.invoke(app, ["monitor"])
        assert result.exit_code == 1
        assert "Failed to connect to database" in result.stdout


def test_monitor_mocked_lock_failure():
    """Test monitor CLI when advisory lock is held by another instance."""
    with (
        patch("sentinelx.cli.main.check_db_connection", return_value=True),
        patch("sentinelx.cli.main.AsyncSessionLocal"),
        patch("sentinelx.cli.main.acquire_advisory_lock", return_value=False),
    ):
        result = runner.invoke(app, ["monitor"])
        assert result.exit_code == 0
        assert "Another instance" in result.stdout


def test_config_command():
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "SentinelX Configuration:" in result.stdout


def test_doctor_command_stubbed(mocker):
    # Mock the doctor checks to always return True for basic CLI testing
    mocker.patch("sentinelx.cli.main.run_doctor_checks", return_value=True)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Running SentinelX Doctor" in result.stdout
