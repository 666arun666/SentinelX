"""`sentinelx doctor` — diagnose the local environment.

Checks Python version, config validity, filesystem permissions, and
connectivity to every infrastructure dependency (Postgres, Redis, Qdrant)
and optional integration (LLM, threat intel APIs). Never raises — every
check is isolated so one broken dependency doesn't hide the rest of the
report.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import StrEnum

import typer
from rich.console import Console
from rich.table import Table

from sentinelx.config.settings import get_settings

console = Console()


class CheckStatus(StrEnum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str


def _check_python() -> CheckResult:
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 11):
        return CheckResult("Python version", CheckStatus.OK, f"{major}.{minor}")
    return CheckResult("Python version", CheckStatus.WARN, f"{major}.{minor} (3.11+ recommended)")


def _check_directories() -> list[CheckResult]:
    settings = get_settings()
    results = []
    for label, path in [
        ("Data directory", settings.data_dir),
        ("Reports directory", settings.reports_dir),
    ]:
        try:
            path.mkdir(parents=True, exist_ok=True)
            writable = os.access(path, os.W_OK)
            results.append(
                CheckResult(
                    label,
                    CheckStatus.OK if writable else CheckStatus.FAIL,
                    str(path) if writable else f"{path} exists but is not writable",
                )
            )
        except OSError as exc:
            results.append(CheckResult(label, CheckStatus.FAIL, str(exc)))
    return results


def _check_log_sources() -> list[CheckResult]:
    settings = get_settings()
    results = []
    for label, path in [
        ("auth.log", settings.monitor_auth_log),
        ("syslog", settings.monitor_syslog),
    ]:
        if not path.exists():
            results.append(
                CheckResult(f"Log source: {label}", CheckStatus.WARN, f"{path} not found")
            )
            continue
        readable = os.access(path, os.R_OK)
        results.append(
            CheckResult(
                f"Log source: {label}",
                CheckStatus.OK if readable else CheckStatus.FAIL,
                str(path) if readable else f"{path} is not readable (permission denied)",
            )
        )

    if settings.monitor_use_journalctl:
        import shutil

        found = shutil.which("journalctl") is not None
        results.append(
            CheckResult(
                "journalctl",
                CheckStatus.OK if found else CheckStatus.WARN,
                "available" if found else "binary not found on PATH",
            )
        )
    if settings.monitor_use_auditd:
        import shutil

        found = shutil.which("auditctl") is not None
        results.append(
            CheckResult(
                "auditd",
                CheckStatus.OK if found else CheckStatus.WARN,
                "available" if found else "auditctl not found on PATH",
            )
        )
    return results


def _check_database() -> CheckResult:
    settings = get_settings()
    try:
        from sqlalchemy import create_engine, text
    except ImportError:
        return CheckResult("PostgreSQL", CheckStatus.SKIP, "sqlalchemy not installed")

    try:
        engine = create_engine(settings.database_url, connect_args={"connect_timeout": 3})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return CheckResult("PostgreSQL", CheckStatus.OK, "connected")
    except Exception as exc:  # noqa: BLE001 - diagnostic tool, must not crash
        return CheckResult("PostgreSQL", CheckStatus.FAIL, _short(exc))


def _check_redis() -> CheckResult:
    settings = get_settings()
    try:
        import redis
    except ImportError:
        return CheckResult("Redis", CheckStatus.SKIP, "redis package not installed")

    try:
        client = redis.from_url(settings.redis_url, socket_connect_timeout=3)
        client.ping()
        return CheckResult("Redis", CheckStatus.OK, "connected")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Redis", CheckStatus.FAIL, _short(exc))


def _check_qdrant() -> CheckResult:
    settings = get_settings()
    try:
        from qdrant_client import QdrantClient
    except ImportError:
        return CheckResult("Qdrant", CheckStatus.SKIP, "qdrant-client not installed")

    try:
        client = QdrantClient(url=settings.qdrant_url, timeout=3)
        client.get_collections()
        return CheckResult("Qdrant", CheckStatus.OK, "connected")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Qdrant", CheckStatus.FAIL, _short(exc))


def _check_llm() -> CheckResult:
    settings = get_settings()
    if settings.llm_configured:
        return CheckResult("LLM (Anthropic)", CheckStatus.OK, "ANTHROPIC_API_KEY set")
    return CheckResult(
        "LLM (Anthropic)",
        CheckStatus.WARN,
        "not configured — AI reasoning stages will be unavailable",
    )


def _check_threat_intel() -> list[CheckResult]:
    settings = get_settings()
    results = []
    for label, configured in [
        ("VirusTotal", settings.virustotal_configured),
        ("AbuseIPDB", settings.abuseipdb_configured),
        ("OpenCTI", settings.opencti_configured),
    ]:
        results.append(
            CheckResult(
                f"Threat intel: {label}",
                CheckStatus.OK if configured else CheckStatus.WARN,
                "configured" if configured else "not configured — mock/demo provider will be used",
            )
        )
    return results


def _short(exc: Exception) -> str:
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
    return text[:120]


def doctor() -> None:
    """Run environment and connectivity diagnostics."""
    results: list[CheckResult] = [_check_python()]
    results += _check_directories()
    results += _check_log_sources()
    results.append(_check_database())
    results.append(_check_redis())
    results.append(_check_qdrant())
    results.append(_check_llm())
    results += _check_threat_intel()

    table = Table(title="SentinelX Doctor", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Detail")

    style_map = {
        CheckStatus.OK: "green",
        CheckStatus.WARN: "yellow",
        CheckStatus.FAIL: "red",
        CheckStatus.SKIP: "dim",
    }
    for r in results:
        table.add_row(
            r.name, f"[{style_map[r.status]}]{r.status.value}[/{style_map[r.status]}]", r.detail
        )

    console.print(table)

    failures = [r for r in results if r.status == CheckStatus.FAIL]
    if failures:
        console.print(f"\n[red bold]{len(failures)} check(s) failed.[/red bold]")
        raise typer.Exit(code=1)

    warnings = [r for r in results if r.status == CheckStatus.WARN]
    if warnings:
        console.print(
            f"\n[yellow]{len(warnings)} optional check(s) not configured — SentinelX will run in degraded/demo mode for those features.[/yellow]"
        )
    else:
        console.print("\n[green bold]All checks passed.[/green bold]")
