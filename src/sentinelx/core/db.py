from datetime import UTC, datetime

import structlog
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sentinelx.core.config import settings
from sentinelx.models.db_models import Event, LogSource

logger = structlog.get_logger(__name__)

# Async Engine
engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)


async def get_db_session() -> AsyncSession:
    """Dependency for getting async DB session."""
    async with AsyncSessionLocal() as session:
        yield session


async def check_db_connection() -> bool:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Database connection failed", error=str(e))
        return False


async def acquire_advisory_lock(session: AsyncSession, lock_id: int = 1001) -> bool:
    """Acquire single-instance monitor guard using pg_advisory_lock."""
    result = await session.execute(text(f"SELECT pg_try_advisory_lock({lock_id})"))
    locked = result.scalar()
    return bool(locked)


async def persist_events_and_cursor(
    session: AsyncSession,
    event_dict: dict,
    source_name: str,
    position_identity: str,
    file_inode: int | None = None,
) -> None:
    """
    At-least-once persistence logic:
    1. INSERT event ON CONFLICT DO NOTHING
    2. Update cursor in log_sources
    3. Commit transaction
    """
    # 1. Insert event
    stmt = insert(Event).values(**event_dict)
    stmt = stmt.on_conflict_do_nothing(index_elements=["event_id"])
    await session.execute(stmt)

    # 2. Update cursor
    update_data = {
        "source": source_name,
        "format": "text",
        "status": "active",
        "last_read_at": datetime.now(UTC),
    }
    # position_identity is either numeric offset or string cursor
    if position_identity.isdigit() and "journal" not in source_name:
        update_data["offset"] = int(position_identity)
        if file_inode:
            update_data["file_inode"] = file_inode
    else:
        update_data["journal_cursor"] = position_identity

    src_stmt = insert(LogSource).values(**update_data)
    # Upsert the log source cursor
    src_stmt = src_stmt.on_conflict_do_update(
        index_elements=["source"], set_=update_data
    )
    await session.execute(src_stmt)

    # 3. Commit
    await session.commit()
