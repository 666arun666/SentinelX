import asyncio

import structlog

logger = structlog.get_logger(__name__)


class BaseCollector:
    """Base class for all SentinelX log collectors."""

    def __init__(self, source_name: str, queue: asyncio.Queue):
        self.source_name = source_name
        self.queue = queue
        self._stop_event = asyncio.Event()
        self.metrics = {
            "events_read": 0,
            "reconnects": 0,
            "failures": 0,
            "backpressure_events": 0,
        }

    async def start(self) -> None:
        """Start the collection loop."""
        try:
            await self._run()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.metrics["failures"] += 1
            logger.error("collector_failed", source=self.source_name, error=str(e))
            raise

    def stop(self) -> None:
        """Signal the collector to stop."""
        self._stop_event.set()

    async def _run(self) -> None:
        """Subclasses must implement the actual loop."""
        raise NotImplementedError

    async def enqueue_payload(self, payload: dict) -> None:
        """Push payload to the queue, tracking backpressure if full."""
        if self.queue.full():
            self.metrics["backpressure_events"] += 1
            logger.warning(
                "backpressure_detected",
                source=self.source_name,
                queue_size=self.queue.qsize(),
            )

        await self.queue.put(payload)

    def get_metrics(self) -> dict:
        return self.metrics.copy()
