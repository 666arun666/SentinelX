import pytest

from sentinelx.tui.app import DashboardApp


@pytest.mark.asyncio
async def test_dashboard_app_startup():
    app = DashboardApp()
    async with app.run_test() as pilot:
        # Dashboard is running
        assert app.title == "SentinelX Dashboard"

        # Check tabs exist
        assert pilot.app.query_one("#findings_table") is not None
        assert pilot.app.query_one("#events_table") is not None
        assert pilot.app.query_one("#sources_table") is not None

        # Test pressing refresh
        await pilot.press("r")
        await pilot.pause()

        # App handles quit
        await pilot.press("q")
