"""`sentinelx status` — quick snapshot of the running system.

Phase 1 implements the command surface and configuration snapshot only.
Once the database layer (Phase 2+) exists, this will report live counts
of investigations, alerts, and monitored log sources instead of static
configuration.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from sentinelx import __version__
from sentinelx.config.settings import get_settings

console = Console()


def status() -> None:
    """Show a snapshot of SentinelX configuration and readiness."""
    settings = get_settings()

    lines = [
        f"[bold]SentinelX[/bold] v{__version__}  ({settings.environment})",
        "",
        f"Database:   {settings.database_url.split('@')[-1]}",
        f"Redis:      {settings.redis_url}",
        f"Qdrant:     {settings.qdrant_url}",
        f"LLM:        {'configured' if settings.llm_configured else 'not configured (demo mode)'}",
        f"LangSmith:  {'enabled' if settings.langsmith_configured else 'disabled'}",
        "",
        "[dim]Live monitoring/investigation counts will appear here once the"
        " monitoring daemon and database layer (Phase 2+) are implemented.[/dim]",
    ]
    console.print(Panel("\n".join(lines), title="Status", expand=False))
