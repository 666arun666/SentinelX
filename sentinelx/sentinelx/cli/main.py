"""SentinelX CLI entrypoint.

Terminal-first interface built with Typer. Each subcommand lives in its
own module under ``sentinelx/cli/`` and is wired in here so `main.py`
stays a thin router.
"""

from __future__ import annotations

import typer
from rich.console import Console

from sentinelx import __version__
from sentinelx.cli import alerts as alerts_cmd
from sentinelx.cli import config as config_cmd
from sentinelx.cli import doctor as doctor_cmd
from sentinelx.cli import investigate as investigate_cmd
from sentinelx.cli import monitor as monitor_cmd
from sentinelx.cli import report as report_cmd
from sentinelx.cli import status as status_cmd
from sentinelx.config.settings import get_settings
from sentinelx.utils.logging import configure_logging

console = Console()

app = typer.Typer(
    name="sentinelx",
    help="SentinelX — AI-powered Linux Security Operations Center.",
    add_completion=True,
)

app.command("monitor")(monitor_cmd.monitor)
app.command("investigate")(investigate_cmd.investigate)
app.command("report")(report_cmd.report)
app.command("alerts")(alerts_cmd.alerts)
app.command("status")(status_cmd.status)
app.command("doctor")(doctor_cmd.doctor)
app.add_typer(config_cmd.config_app, name="config", help="View and validate configuration.")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", help="Show the SentinelX version and exit.", is_eager=True
    ),
) -> None:
    """SentinelX — AI-powered Linux SOC monitoring and investigation platform."""
    settings = get_settings()
    configure_logging(level=settings.log_level)

    if version:
        console.print(f"SentinelX v{__version__}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


if __name__ == "__main__":
    app()
