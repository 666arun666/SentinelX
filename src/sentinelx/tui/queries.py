import structlog
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from sentinelx.core.db import AsyncSessionLocal
from sentinelx.models.db_models import Event, Finding, LogSource

logger = structlog.get_logger(__name__)


async def fetch_recent_findings(limit: int = 50) -> list[Finding]:
    """Fetch recent findings from the database."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(Finding).order_by(Finding.created_at.desc()).limit(limit)
            result = await session.execute(stmt)
            # Must expunge them from session since we use them after session closes
            findings = result.scalars().all()
            for f in findings:
                session.expunge(f)
            return list(findings)
    except SQLAlchemyError as e:
        logger.error("tui_fetch_findings_error", error=str(e))
        return []
    except Exception as e:  # noqa: BLE001
        logger.error("tui_fetch_findings_unknown_error", error=str(e))
        return []


async def fetch_recent_events(limit: int = 100) -> list[Event]:
    """Fetch recent events from the database."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(Event).order_by(Event.event_time.desc()).limit(limit)
            result = await session.execute(stmt)
            events = result.scalars().all()
            for e in events:
                session.expunge(e)
            return list(events)
    except SQLAlchemyError as e:
        logger.error("tui_fetch_events_error", error=str(e))
        return []
    except Exception as e:  # noqa: BLE001
        logger.error("tui_fetch_events_unknown_error", error=str(e))
        return []


async def fetch_log_sources() -> list[LogSource]:
    """Fetch log source status."""
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(LogSource).order_by(LogSource.last_read_at.desc())
            result = await session.execute(stmt)
            sources = result.scalars().all()
            for s in sources:
                session.expunge(s)
            return list(sources)
    except SQLAlchemyError as e:
        logger.error("tui_fetch_sources_error", error=str(e))
        return []
    except Exception as e:  # noqa: BLE001
        logger.error("tui_fetch_sources_unknown_error", error=str(e))
        return []
