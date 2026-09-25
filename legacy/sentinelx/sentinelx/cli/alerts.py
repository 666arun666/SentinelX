"""`sentinelx alerts` — list current alerts / suspicious findings.

Real implementation lands in Phase 3 (deterministic detection engine).
"""

from __future__ import annotations

from rich.console import Console

console = Console()


def alerts() -> None:
    """List active alerts and suspicious findings."""
    console.print(
        "[yellow]`sentinelx alerts` is not implemented yet.[/yellow]\n"
        "It will list findings from the deterministic + LLM detection engine, "
        "backed by the `agent_findings` table.\n"
        "Planned for Phase 3 of the build."
    )
