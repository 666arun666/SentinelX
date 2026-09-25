from collections.abc import Iterable

from textual import work
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Header, TabbedContent, TabPane

from sentinelx.models.db_models import Event, Finding, LogSource
from sentinelx.tui.queries import (
    fetch_log_sources,
    fetch_recent_events,
    fetch_recent_findings,
)


class DashboardApp(App[None]):
    """SentinelX Terminal Dashboard."""

    TITLE = "SentinelX Dashboard"

    CSS = """
    TabbedContent, ContentSwitcher, TabPane {
        height: 1fr;
    }

    DataTable {
        height: 100%;
        width: 100%;
    }
    """

    BINDINGS = [  # noqa: RUF012
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        with TabbedContent():
            with TabPane("Findings"):
                yield DataTable(id="findings_table")
            with TabPane("Events"):
                yield DataTable(id="events_table")
            with TabPane("Sources"):
                yield DataTable(id="sources_table")
        yield Footer()

    def on_mount(self) -> None:
        """Setup layout and start auto-refresh."""
        # Initialize Findings table
        findings_table = self.query_one("#findings_table", DataTable)
        findings_table.add_columns("Time", "Severity", "Title", "Rule ID")

        # Initialize Events table
        events_table = self.query_one("#events_table", DataTable)
        events_table.add_columns("Time", "Source", "Host", "Message")

        # Initialize Sources table
        sources_table = self.query_one("#sources_table", DataTable)
        sources_table.add_columns("Source", "Format", "Status", "Last Read")

        # Initial fetch
        self.action_refresh()

        # Auto-refresh every 5 seconds
        self.set_interval(5.0, self.action_refresh)

    @work(exclusive=True)
    async def action_refresh(self) -> None:
        """Fetch data asynchronously and update tables."""
        findings = await fetch_recent_findings()
        events = await fetch_recent_events()
        sources = await fetch_log_sources()

        self.update_tables(findings, events, sources)

    def update_tables(
        self,
        findings: Iterable[Finding],
        events: Iterable[Event],
        sources: Iterable[LogSource],
    ) -> None:
        """Update tables safely in the UI thread."""
        findings_table = self.query_one("#findings_table", DataTable)
        findings_table.clear()
        for f in findings:
            findings_table.add_row(
                f.created_at.strftime("%Y-%m-%d %H:%M:%S") if f.created_at else "",
                f.severity.upper() if f.severity else "UNKNOWN",
                f.title or "Unknown",
                f.rule_id or "Unknown",
            )

        events_table = self.query_one("#events_table", DataTable)
        events_table.clear()
        for e in events:
            # Prefer message, fallback to raw_log truncated
            msg = e.message
            if not msg and e.raw_log:
                msg = e.raw_log[:100] + ("..." if len(e.raw_log) > 100 else "")

            events_table.add_row(
                e.event_time.strftime("%Y-%m-%d %H:%M:%S") if e.event_time else "",
                e.source or "",
                e.hostname or "",
                msg or "",
            )

        sources_table = self.query_one("#sources_table", DataTable)
        sources_table.clear()
        for s in sources:
            sources_table.add_row(
                s.source or "",
                s.format or "",
                s.status or "",
                s.last_read_at.strftime("%Y-%m-%d %H:%M:%S") if s.last_read_at else "",
            )
