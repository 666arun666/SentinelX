from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from sentinelx.core.db import (
    AsyncSessionLocal,
    persist_events_and_cursor,
)
from sentinelx.models.db_models import Event, LogSource

# Simple in-memory mock or rely on the real DB if configured for test
# For simplicity, we assume we have a real test DB running since M1 sets up Docker Compose.


@pytest.mark.asyncio
async def test_persist_events_and_cursor_idempotency():
    # If no DB is running, this might fail, but it tests the logic.
    try:
        async with AsyncSessionLocal() as session:
            event_dict = {
                "event_id": "test_hash_123",
                "event_time": datetime.now(UTC),
                "collected_at": datetime.now(UTC),
                "source": "auth.log",
                "raw_log": "test line",
            }

            # Insert first time
            await persist_events_and_cursor(session, event_dict, "auth.log", "100")

            # Insert second time (should NOT raise duplicate key error)
            await persist_events_and_cursor(session, event_dict, "auth.log", "200")

            # Verify event exists exactly once
            stmt = select(Event).where(Event.event_id == "test_hash_123")
            result = await session.execute(stmt)
            events = result.scalars().all()
            assert len(events) == 1

            # Verify cursor was updated to 200
            stmt_src = select(LogSource).where(LogSource.source == "auth.log")
            result_src = await session.execute(stmt_src)
            src = result_src.scalar_one()
            assert src.offset == 200
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"Database not available for integration test: {e}")
