"""`sentinelx config` — view and validate configuration."""

from __future__ import annotations

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from sentinelx.config.settings import Settings, get_settings

console = Console()
config_app = typer.Typer(no_args_is_help=True)

_SECRET_FIELDS = {
    "anthropic_api_key",
    "langsmith_api_key",
    "virustotal_api_key",
    "abuseipdb_api_key",
    "opencti_api_key",
}


def _mask(field: str, value: object) -> str:
    if value is None:
        return "[dim]not set[/dim]"
    if field in _SECRET_FIELDS:
        s = str(value)
        return f"{'*' * max(len(s) - 4, 0)}{s[-4:]}" if len(s) > 4 else "****"
    return str(value)


@config_app.command("show")
def show() -> None:
    """Print the currently loaded configuration (secrets masked)."""
    settings = get_settings()
    table = Table(title="SentinelX Configuration")
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    for field in type(settings).model_fields:
        table.add_row(field, _mask(field, getattr(settings, field)))

    console.print(table)


@config_app.command("validate")
def validate() -> None:
    """Validate configuration (.env / environment variables) and exit non-zero on error."""
    try:
        Settings()
    except ValidationError as exc:
        console.print("[red bold]Configuration is invalid:[/red bold]")
        for err in exc.errors():
            loc = ".".join(str(x) for x in err["loc"])
            console.print(f"  [red]- {loc}: {err['msg']}[/red]")
        raise typer.Exit(code=1) from exc

    console.print("[green bold]Configuration is valid.[/green bold]")
