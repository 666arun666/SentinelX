"""`sentinelx monitor` — live SOC dashboard and monitoring daemon.

This command's real implementation lands in Phase 2 (log collectors) and
Phase 10 (Textual dashboard). It is wired into the CLI now, with a clear
explanation, so the command surface described in the architecture is
stable from the start.
"""

from __future__ import annotations

import typer
from rich.console import Console

console = Console()


def monitor(
    sample: bool = typer.Option(
        False, "--sample", help="(Coming in Phase 10) Run against bundled sample logs."
    ),
) -> None:
    """Start continuous host monitoring with the live terminal dashboard."""
    console.print(
        "[yellow]`sentinelx monitor` is not implemented yet.[/yellow]\n"
        "It will start the log collectors (auth.log / syslog / journalctl / auditd), "
        "normalize events, and render the live Textual dashboard.\n"
        "Planned for Phase 2 (collectors) and Phase 10 (dashboard) of the build."
    )
    raise typer.Exit(code=0)
