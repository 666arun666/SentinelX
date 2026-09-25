import asyncio
import signal
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import structlog
import typer

from sentinelx.collection.manager import CollectionManager
from sentinelx.core.db import (
    AsyncSessionLocal,
    acquire_advisory_lock,
    check_db_connection,
)
from sentinelx.core.doctor import print_config_status, run_doctor_checks
from sentinelx.core.log_setup import configure_logging

# Initialize logging for the CLI
configure_logging()

logger = structlog.get_logger(__name__)
app = typer.Typer(help="SentinelX - Linux Security Monitoring Daemon")


@app.command()
def monitor():
    """Start the M2 log collection monitor."""

    async def _run_monitor():
        # Check DB
        if not await check_db_connection():
            typer.secho("Failed to connect to database.", fg="red")
            sys.exit(1)

        async with AsyncSessionLocal() as session:
            # Acquire lock
            locked = await acquire_advisory_lock(session)
            if not locked:
                typer.secho(
                    "Another instance of SentinelX monitor is already running. Exiting.",
                    fg="yellow",
                )
                sys.exit(0)

            typer.secho(
                "Advisory lock acquired. Starting Collection Manager...", fg="green"
            )

            from sentinelx.agents.worker import EnrichmentWorker

            enrichment_queue = asyncio.Queue(maxsize=1000)
            worker = EnrichmentWorker(enrichment_queue)
            await worker.start()

            manager = CollectionManager(enrichment_queue=enrichment_queue)

            # Setup graceful shutdown
            loop = asyncio.get_running_loop()
            stop_event = asyncio.Event()

            def handle_sigint():
                typer.secho("\nShutting down gracefully...", fg="yellow")
                stop_event.set()

            loop.add_signal_handler(signal.SIGINT, handle_sigint)
            loop.add_signal_handler(signal.SIGTERM, handle_sigint)

            manager_task = asyncio.create_task(manager.start())

            await stop_event.wait()
            await manager.stop()
            await worker.stop()
            await manager_task
            manager.print_metrics()
            typer.secho("SentinelX monitor stopped.", fg="green")

    asyncio.run(_run_monitor())


@app.command()
def status():
    """Show current daemon status."""
    from rich.console import Console
    from rich.table import Table

    from sentinelx.tui.queries import fetch_log_sources

    # Check DB
    if not asyncio.run(check_db_connection()):
        typer.secho("Failed to connect to database.", fg="red")
        sys.exit(1)

    sources = asyncio.run(fetch_log_sources())
    console = Console()

    if not sources:
        console.print("[yellow]No log sources found.[/yellow]")
        return

    table = Table(title="Log Sources Status")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Last Read")

    for s in sources:
        table.add_row(
            s.source or "",
            s.status or "",
            s.last_read_at.strftime("%Y-%m-%d %H:%M:%S") if s.last_read_at else "",
        )

    console.print(table)


@app.command()
def doctor():
    """Check connectivity to required infrastructure."""
    typer.echo("Running SentinelX Doctor...")
    success = run_doctor_checks()
    if not success:
        raise typer.Exit(code=1)


@app.command()
def config():
    """Display current configuration safely."""
    typer.echo("SentinelX Configuration:")
    print_config_status()
    typer.echo("Other settings are loaded.")


@app.command()
def investigate(case_id: str):
    """Trigger investigation for a case."""
    typer.echo(f"Investigating case {case_id}... (Not implemented in M1)")


@app.command()
def report(case_id: str):
    """Generate a report for a case."""
    typer.echo(f"Generating report for case {case_id}... (Not implemented in M1)")


@app.command()
def alerts():
    """List recent alerts."""
    from rich.console import Console
    from rich.table import Table

    from sentinelx.tui.queries import fetch_recent_findings

    if not asyncio.run(check_db_connection()):
        typer.secho("Failed to connect to database.", fg="red")
        sys.exit(1)

    findings = asyncio.run(fetch_recent_findings(10))
    console = Console()

    if not findings:
        console.print("[yellow]No recent alerts found.[/yellow]")
        return

    table = Table(title="Recent Alerts")
    table.add_column("Time")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Rule ID")

    for f in findings:
        table.add_row(
            f.created_at.strftime("%Y-%m-%d %H:%M:%S") if f.created_at else "",
            f.severity.upper() if f.severity else "",
            f.title or "",
            f.rule_id or "",
        )

    console.print(table)


@app.command()
def dashboard():
    """Start the SentinelX Terminal Dashboard."""
    if not asyncio.run(check_db_connection()):
        typer.secho("Failed to connect to database.", fg="red")
        sys.exit(1)

    from sentinelx.tui.app import DashboardApp

    tui_app = DashboardApp()
    tui_app.run()


if __name__ == "__main__":
    app()
