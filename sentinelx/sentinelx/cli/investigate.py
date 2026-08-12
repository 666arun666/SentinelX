"""`sentinelx investigate` — run the LangGraph investigation workflow.

Real implementation lands in Phase 4 (LangGraph skeleton) through Phase 9
(human approval + reports). Wired into the CLI now for a stable command
surface.
"""

from __future__ import annotations

import typer
from rich.console import Console

console = Console()


def investigate(
    sample: bool = typer.Option(
        False, "--sample", help="(Coming in Phase 4+) Run the workflow against bundled sample logs."
    ),
    investigation_id: str = typer.Option(
        None, "--id", help="(Coming in Phase 4+) Re-open an existing investigation by ID."
    ),
) -> None:
    """Trigger or resume an AI-assisted investigation."""
    console.print(
        "[yellow]`sentinelx investigate` is not implemented yet.[/yellow]\n"
        "It will run the LangGraph multi-agent workflow: Supervisor -> Detection -> "
        "Threat Intel -> Correlation -> MITRE Mapping -> Risk Scoring -> Evidence "
        "Validation -> Human Approval -> Report Generation.\n"
        "Planned for Phase 4 through Phase 9 of the build."
    )
    raise typer.Exit(code=0)
