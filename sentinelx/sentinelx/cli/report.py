"""`sentinelx report` — generate or view investigation reports.

Real implementation lands in Phase 9 (PDF report generation).
"""

from __future__ import annotations

import typer
from rich.console import Console

console = Console()


def report(
    investigation_id: str = typer.Argument(
        None, help="(Coming in Phase 9) Investigation ID to report on."
    ),
) -> None:
    """Generate or view a PDF investigation report."""
    console.print(
        "[yellow]`sentinelx report` is not implemented yet.[/yellow]\n"
        "It will render a PDF investigation report (Executive Summary, Timeline, "
        "IOCs, MITRE mapping, Risk Assessment, Evidence, Recommended Actions) and "
        "store the report path in the database.\n"
        "Planned for Phase 9 of the build."
    )
    raise typer.Exit(code=0)
