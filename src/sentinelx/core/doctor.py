import asyncio

from rich.console import Console

from sentinelx.core.config import settings
from sentinelx.core.db import check_db_connection
from sentinelx.core.infrastructure import (
    check_qdrant_connection,
    check_redis_connection,
)

console = Console()


def print_config_status():
    """Print configuration state safely without exposing secrets."""
    console.print("[bold]Configuration Status:[/bold]")

    console.print(
        f"Database: {'[green]CONFIGURED[/green]' if settings.DATABASE_URL else '[red]NOT CONFIGURED[/red]'}"
    )
    console.print(
        f"Redis: {'[green]CONFIGURED[/green]' if settings.REDIS_URL else '[red]NOT CONFIGURED[/red]'}"
    )
    console.print(
        f"Qdrant: {'[green]CONFIGURED[/green]' if settings.QDRANT_URL else '[red]NOT CONFIGURED[/red]'}"
    )

    console.print(
        f"Anthropic API: {'[green]CONFIGURED[/green]' if settings.ANTHROPIC_API_KEY else '[yellow]NOT CONFIGURED[/yellow]'}"
    )
    console.print(
        f"VirusTotal API: {'[green]CONFIGURED[/green]' if settings.VIRUSTOTAL_API_KEY else '[yellow]NOT CONFIGURED[/yellow]'}"
    )
    console.print(
        f"AbuseIPDB API: {'[green]CONFIGURED[/green]' if settings.ABUSEIPDB_API_KEY else '[yellow]NOT CONFIGURED[/yellow]'}"
    )
    console.print(
        f"OpenCTI API: {'[green]CONFIGURED[/green]' if settings.OPENCTI_API_KEY else '[yellow]NOT CONFIGURED[/yellow]'}"
    )

    console.print("")


async def run_doctor_checks_async() -> bool:
    """Run all connectivity checks. Return True if all succeed."""
    pg = await check_db_connection()
    if pg:
        console.print("PostgreSQL    [green]OK[/green]")
    else:
        console.print("PostgreSQL    [red]ERROR[/red]")

    rd = await check_redis_connection()
    if rd:
        console.print("Redis         [green]OK[/green]")
    else:
        console.print("Redis         [red]ERROR[/red]")

    qd = await check_qdrant_connection()
    if qd:
        console.print("Qdrant        [green]OK[/green]")
    else:
        console.print("Qdrant        [red]ERROR[/red]")

    return pg and rd and qd


def run_doctor_checks() -> bool:
    """Synchronous wrapper for doctor checks."""
    print_config_status()
    console.print("[bold]Infrastructure Status:[/bold]")
    return asyncio.run(run_doctor_checks_async())
