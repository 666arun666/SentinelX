import asyncio
from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from sentinelx.collection.file_collector import FileCollector
from sentinelx.collection.journal_collector import JournalCollector
from sentinelx.collection.parsers import (
    parse_auditd,
    parse_auth_log,
    parse_journal_json,
    parse_syslog,
)
from sentinelx.core.config import settings
from sentinelx.core.db import AsyncSessionLocal, persist_events_and_cursor
from sentinelx.detection.engine import DetectionEngine
from sentinelx.models.db_models import LogSource
from sentinelx.models.event import NormalizedEvent, generate_event_id

logger = structlog.get_logger(__name__)


class CollectionManager:
    def __init__(self, enrichment_queue: asyncio.Queue[str] | None = None):
        # Default bounded queue to handle backpressure
        self.queue = asyncio.Queue(
            maxsize=getattr(settings, "BACKPRESSURE_QUEUE_SIZE", 10000)
        )
        self.collectors = []
        self._stop_event = asyncio.Event()
        self.tasks = []
        self.detection_queue = asyncio.Queue(
            maxsize=getattr(settings, "DETECTION_QUEUE_SIZE", 1000)
        )
        self.detection_engine = DetectionEngine(
            rules_dir="rules", enrichment_queue=enrichment_queue
        )
        self.metrics = {
            "events_processed": 0,
            "parse_failures": 0,
            "backpressure_events": 0,
            "db_failures": 0,
            "detection_failures": 0,
            "detection_queue_full_blocks": 0,
        }

    async def _get_source_state(self, source_name: str) -> dict:
        async with AsyncSessionLocal() as session:
            stmt = select(LogSource).where(LogSource.source == source_name)
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()
            if record:
                return {
                    "offset": record.offset or 0,
                    "file_inode": record.file_inode,
                    "journal_cursor": record.journal_cursor,
                }
        return {}

    async def start(self):
        logger.info("collection_manager_starting")

        # Load states and initialize collectors
        # 1. auth.log
        state = await self._get_source_state("auth.log")
        auth_collector = FileCollector(
            "auth.log",
            "/var/log/auth.log",
            self.queue,
            initial_inode=state.get("file_inode"),
            initial_offset=state.get("offset", 0),
        )
        self.collectors.append(auth_collector)

        # 2. syslog
        state = await self._get_source_state("syslog")
        syslog_collector = FileCollector(
            "syslog",
            "/var/log/syslog",
            self.queue,
            initial_inode=state.get("file_inode"),
            initial_offset=state.get("offset", 0),
        )
        self.collectors.append(syslog_collector)

        # 3. journalctl
        state = await self._get_source_state("journalctl")
        journal_collector = JournalCollector(
            "journalctl", self.queue, initial_cursor=state.get("journal_cursor")
        )
        self.collectors.append(journal_collector)

        # 4. auditd
        state = await self._get_source_state("auditd")
        audit_collector = FileCollector(
            "auditd",
            "/var/log/audit/audit.log",
            self.queue,
            initial_inode=state.get("file_inode"),
            initial_offset=state.get("offset", 0),
        )
        self.collectors.append(audit_collector)

        # Start collector tasks
        for collector in self.collectors:
            t = asyncio.create_task(collector.start())
            self.tasks.append(t)

        # Start consumer loop
        self.tasks.append(asyncio.create_task(self._consume_queue()))
        self.tasks.append(asyncio.create_task(self._consume_detection_queue()))

    async def stop(self):
        logger.info("collection_manager_stopping")
        self._stop_event.set()
        for collector in self.collectors:
            collector.stop()

        # Wait for tasks to wind down
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

    async def _consume_queue(self):
        while not self._stop_event.is_set():
            try:
                # Use timeout to allow checking _stop_event periodically
                payload = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except TimeoutError:
                continue

            try:
                await self._process_payload(payload)
            except Exception as e:  # noqa: BLE001
                logger.error(
                    "payload_processing_failed",
                    error=str(e),
                    source=payload.get("source"),
                )
            finally:
                self.queue.task_done()

    async def _consume_detection_queue(self):
        logger.info("detection_consumer_started")
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(self.detection_queue.get(), timeout=1.0)
            except TimeoutError:
                continue

            try:
                await self.detection_engine.evaluate_event(event)
            except Exception as e:  # noqa: BLE001
                self.metrics["detection_failures"] += 1
                logger.error(
                    "detection_evaluation_failed_fatal",
                    error=str(e),
                    event_id=event.event_id,
                )
            finally:
                self.detection_queue.task_done()

    async def _process_payload(self, payload: dict):
        source = payload["source"]
        raw_log = payload["raw_log"]
        pos_id = payload["position_identity"]
        inode = payload.get("file_inode")

        # 1. Parse deterministically
        parsed = None
        if source == "auth.log":
            parsed = parse_auth_log(raw_log)
        elif source == "syslog":
            parsed = parse_syslog(raw_log)
        elif source == "journalctl":
            parsed = parse_journal_json(raw_log)
        elif source == "auditd":
            parsed = parse_auditd(raw_log)

        if not parsed:
            self.metrics["parse_failures"] += 1
            return

        # 2. Normalize
        event_id = generate_event_id(source, pos_id, raw_log)

        # Merge defaults
        parsed["event_id"] = event_id
        parsed["source"] = source
        parsed["collected_at"] = datetime.now(UTC)  # UTC logically

        try:
            event_model = NormalizedEvent(**parsed)
        except Exception as e:  # noqa: BLE001
            self.metrics["parse_failures"] += 1
            logger.warning("normalization_failed", error=str(e), raw_log=raw_log)
            return

        # 3. Persist At-Least-Once in Transaction
        # Retry loop for DB failure
        while not self._stop_event.is_set():
            try:
                async with AsyncSessionLocal() as session:
                    await persist_events_and_cursor(
                        session=session,
                        event_dict=event_model.model_dump(),
                        source_name=source,
                        position_identity=pos_id,
                        file_inode=inode,
                    )
                self.metrics["events_processed"] += 1

                # Forward to detection engine asynchronously via bounded queue
                if self.detection_queue.full():
                    self.metrics["detection_queue_full_blocks"] += 1
                    logger.warning("detection_queue_full_blocking_ingestion")
                await self.detection_queue.put(event_model)

                break  # Success
            except Exception as e:  # noqa: BLE001
                self.metrics["db_failures"] += 1
                logger.error("db_persistence_failed_retrying", error=str(e))
                await asyncio.sleep(5.0)

    def print_metrics(self):
        logger.info("collection_metrics", manager=self.metrics)
        for c in self.collectors:
            logger.info(
                "collector_metrics", source=c.source_name, metrics=c.get_metrics()
            )
