import asyncio
import logging

from sqlalchemy import select

from sentinelx.agents.correlation import CorrelationAgent
from sentinelx.agents.mitre import MitreMappingAgent
from sentinelx.agents.models import CorrelationResult, EnrichmentResult, MitreResult
from sentinelx.agents.supervisor import create_supervisor_graph
from sentinelx.agents.threat_intel import ThreatIntelClient, get_redis_client
from sentinelx.core.db import AsyncSessionLocal
from sentinelx.models.db_models import Event, Finding

logger = logging.getLogger(__name__)


class EnrichmentWorker:
    def __init__(self, queue: asyncio.Queue[str]):
        self.queue = queue
        self._running = False
        self._task: asyncio.Task | None = None
        self.ti_client: ThreatIntelClient | None = None
        self.mitre_agent: MitreMappingAgent | None = None
        self.correlation_agent: CorrelationAgent | None = None

    async def start(self) -> None:
        self._running = True
        redis = await get_redis_client()
        self.ti_client = ThreatIntelClient(redis)
        self.mitre_agent = MitreMappingAgent()
        self.correlation_agent = CorrelationAgent()
        self._task = asyncio.create_task(self._process_loop())
        logger.info("Enrichment and M6 agent worker started.")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Enrichment and M6 agent worker stopped.")

    async def _process_loop(self) -> None:
        while self._running:
            try:
                finding_id = await self.queue.get()
                await self._process_finding(finding_id)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:  # noqa: BLE001
                logger.error("Enrichment worker loop error: %s", e)

    async def _process_finding(self, finding_id: str) -> None:
        if not self.ti_client:
            return

        graph = create_supervisor_graph(
            client=self.ti_client,
            mitre_agent=self.mitre_agent,
            correlation_agent=self.correlation_agent,
        )

        try:
            async with AsyncSessionLocal() as session:
                # Fetch finding and associated event
                stmt = select(Finding).where(Finding.finding_id == finding_id)
                finding = (await session.execute(stmt)).scalar_one_or_none()
                if not finding:
                    return

                stmt = select(Event).where(Event.event_id == finding.event_id)
                event = (await session.execute(stmt)).scalar_one_or_none()
                if not event:
                    return

                initial_state = {
                    "finding": finding,
                    "event": event,
                    "enrichment_result": EnrichmentResult(status="in_progress"),
                    "correlation_result": CorrelationResult(
                        correlation_status="isolated"
                    ),
                    "mitre_result": MitreResult(status="not_attempted"),
                    "ips": [],
                    "hashes": [],
                    "domains": [],
                    "vt_done": False,
                    "abuseipdb_done": False,
                }

                result_state = await graph.ainvoke(initial_state)

                enrichment_result: EnrichmentResult = result_state["enrichment_result"]
                correlation_result: CorrelationResult = result_state[
                    "correlation_result"
                ]
                mitre_result: MitreResult = result_state["mitre_result"]

                # Atomic and scoped update: ONLY update permitted JSON fields
                finding.enrichments = enrichment_result.model_dump()
                finding.correlations = correlation_result.model_dump()
                finding.mitre_tags = mitre_result.model_dump()

                await session.commit()
                logger.info(
                    "Processed finding %s: TI=%s, Correlation=%s, MITRE=%s",
                    finding_id,
                    enrichment_result.status,
                    correlation_result.correlation_status,
                    mitre_result.status,
                )

        except Exception as e:  # noqa: BLE001
            logger.error("Failed to process finding %s: %s", finding_id, e)
            # Fail-safe update: Record failed status without modifying M3 authoritative fields
            try:
                async with AsyncSessionLocal() as session:
                    stmt = select(Finding).where(Finding.finding_id == finding_id)
                    finding = (await session.execute(stmt)).scalar_one_or_none()
                    if finding:
                        if not finding.enrichments:
                            finding.enrichments = EnrichmentResult(
                                status="failed"
                            ).model_dump()
                        if not finding.correlations:
                            finding.correlations = CorrelationResult(
                                correlation_status="failed", error_type="worker_error"
                            ).model_dump()
                        if not finding.mitre_tags:
                            finding.mitre_tags = MitreResult(
                                status="failed", error_type="worker_error"
                            ).model_dump()
                        await session.commit()
            except Exception:  # noqa: BLE001, S110
                pass
