import redis.asyncio as redis
import structlog
from qdrant_client import QdrantClient

from sentinelx.core.config import settings

logger = structlog.get_logger(__name__)


async def check_redis_connection() -> bool:
    try:
        client = redis.from_url(settings.REDIS_URL, socket_connect_timeout=5)
        await client.ping()
        await client.aclose()
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Redis connection failed", error=str(e))
        return False


async def check_qdrant_connection() -> bool:
    try:
        client = QdrantClient(url=settings.QDRANT_URL, timeout=5)
        # Using synchronous get_collections just for a simple connectivity check
        client.get_collections()
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Qdrant connection failed", error=str(e))
        return False
