import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from openai import AsyncOpenAI
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qmodels

from sentinelx.agents.models import CorrelationResult
from sentinelx.core.config import settings
from sentinelx.models.db_models import Event, Finding

logger = logging.getLogger(__name__)

EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIM = 1536


class QdrantHit:
    def __init__(self, id: Any, score: float, payload: dict[str, Any] | None = None):
        self.id = id
        self.score = score
        self.payload = payload or {}


class CorrelationAgent:
    def __init__(
        self,
        openai_key: str | None = None,
        qdrant_url: str | None = None,
        collection_name: str | None = None,
    ):
        self.openai_key = openai_key or settings.OPENAI_API_KEY
        self.qdrant_url = qdrant_url or settings.QDRANT_URL
        self.collection_name = collection_name or settings.QDRANT_COLLECTION_NAME
        self.similarity_threshold = settings.CORRELATION_SIMILARITY_THRESHOLD
        self.window_seconds = settings.CORRELATION_WINDOW_SECONDS
        self._qdrant_client: AsyncQdrantClient | None = None

    async def get_qdrant_client(self) -> AsyncQdrantClient:
        if self._qdrant_client is None:
            self._qdrant_client = AsyncQdrantClient(
                url=self.qdrant_url, timeout=5.0, check_compatibility=False
            )
        return self._qdrant_client

    async def ensure_collection_exists(self) -> bool:
        """Ensure the target Qdrant collection exists idempotently."""
        try:
            client = await self.get_qdrant_client()
            collections = await client.get_collections()
            exists = any(
                c.name == self.collection_name for c in collections.collections
            )
            if not exists:
                await client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=qmodels.VectorParams(
                        size=EMBEDDING_DIM,
                        distance=qmodels.Distance.COSINE,
                    ),
                )
                logger.info("Created Qdrant collection '%s'", self.collection_name)
            return True
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to verify/create Qdrant collection: %s", e)
            return False

    async def search_points(self, vector: list[float], limit: int = 5) -> list[Any]:
        """Search similar vectors supporting both modern and legacy Qdrant server APIs."""
        client = await self.get_qdrant_client()
        try:
            query_res = await client.query_points(
                collection_name=self.collection_name,
                query=vector,
                limit=limit,
                with_payload=True,
            )
            return query_res.points
        except Exception as e:  # noqa: BLE001
            logger.debug("query_points failed, attempting legacy /points/search: %s", e)
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as http_client:
                url = f"{self.qdrant_url.rstrip('/')}/collections/{self.collection_name}/points/search"
                resp = await http_client.post(
                    url,
                    json={"vector": vector, "limit": limit, "with_payload": True},
                )
                resp.raise_for_status()
                data = resp.json()
                results: list[Any] = []
                for item in data.get("result", []):
                    results.append(
                        QdrantHit(
                            id=item.get("id"),
                            score=item.get("score", 0.0),
                            payload=item.get("payload") or {},
                        )
                    )
                return results

    def build_correlation_text(
        self,
        finding: Finding,
        event: Event | None = None,
        enrichments: dict[str, Any] | None = None,
    ) -> str:
        """Construct canonical correlation text from normalized finding context."""
        parts = [
            f"Rule: {finding.rule_id}",
            f"Title: {finding.title}",
            f"Severity: {finding.severity}",
        ]

        if event:
            if event.source:
                parts.append(f"Source: {event.source}")
            if event.event_type:
                parts.append(f"EventType: {event.event_type}")
            if event.source_ip:
                parts.append(f"SourceIP: {event.source_ip}")
            if event.destination_ip:
                parts.append(f"DestIP: {event.destination_ip}")
            if event.username:
                parts.append(f"User: {event.username}")
            if event.process:
                parts.append(f"Process: {event.process}")
            if event.indicators:
                parts.append(f"Indicators: {json.dumps(event.indicators, default=str)}")

        if finding.evidence:
            parts.append(f"Evidence: {json.dumps(finding.evidence, default=str)}")

        if enrichments:
            parts.append(f"ThreatIntel: {json.dumps(enrichments, default=str)}")

        return "\n".join(parts)

    async def generate_embedding(self, text: str) -> list[float] | None:
        """Generate vector embedding using OpenAI text-embedding-3-small."""
        if not self.openai_key:
            return None

        try:
            client = AsyncOpenAI(api_key=self.openai_key, timeout=10.0)
            res = await client.embeddings.create(
                model=EMBEDDING_MODEL,
                input=text,
            )
            return res.data[0].embedding
        except Exception as e:  # noqa: BLE001
            logger.warning("Embedding generation failed: %s", e)
            return None

    async def correlate_finding(
        self,
        finding: Finding,
        event: Event | None = None,
        enrichments: dict[str, Any] | None = None,
    ) -> CorrelationResult:
        """Perform semantic similarity search and temporal correlation against Qdrant."""
        if not self.openai_key:
            return CorrelationResult(
                correlation_status="isolated",
                error_type="missing_api_key",
                max_similarity_score=0.0,
                related_finding_ids=[],
            )

        correlation_text = self.build_correlation_text(finding, event, enrichments)
        vector = await self.generate_embedding(correlation_text)
        if vector is None:
            return CorrelationResult(
                correlation_status="failed",
                error_type="embedding_failed",
                max_similarity_score=0.0,
                related_finding_ids=[],
            )

        try:
            collection_ready = await self.ensure_collection_exists()
            if not collection_ready:
                return CorrelationResult(
                    correlation_status="failed",
                    error_type="qdrant_unavailable",
                    max_similarity_score=0.0,
                    related_finding_ids=[],
                )

            client = await self.get_qdrant_client()

            # Search top 5 most similar findings
            search_results = await self.search_points(vector, limit=5)

            current_created = (
                finding.created_at
                if finding.created_at.tzinfo
                else finding.created_at.replace(tzinfo=UTC)
            )

            matched_ids: list[str] = []
            max_score = 0.0
            cluster_id: str | None = None

            for hit in search_results:
                hit_payload = hit.payload or {}
                hit_finding_id = hit_payload.get("finding_id")

                # Exclude self
                if hit_finding_id == finding.finding_id:
                    continue

                score = float(hit.score)
                max_score = max(max_score, score)

                if score >= self.similarity_threshold:
                    # Check temporal window
                    hit_time_str = hit_payload.get("created_at")
                    is_in_window = True
                    if hit_time_str:
                        try:
                            hit_time = datetime.fromisoformat(hit_time_str)
                            if not hit_time.tzinfo:
                                hit_time = hit_time.replace(tzinfo=UTC)
                            diff_seconds = abs(
                                (current_created - hit_time).total_seconds()
                            )
                            if diff_seconds > self.window_seconds:
                                is_in_window = False
                        except Exception:  # noqa: BLE001, S110
                            pass

                    if is_in_window and hit_finding_id:
                        matched_ids.append(hit_finding_id)
                        if not cluster_id and hit_payload.get("cluster_id"):
                            cluster_id = hit_payload.get("cluster_id")

            if matched_ids:
                if not cluster_id:
                    cluster_id = str(uuid.uuid4())
                result = CorrelationResult(
                    correlation_status="correlated",
                    cluster_id=cluster_id,
                    related_finding_ids=matched_ids,
                    max_similarity_score=max_score,
                    correlation_type="temporal_and_semantic",
                )
            else:
                result = CorrelationResult(
                    correlation_status="isolated",
                    cluster_id=None,
                    related_finding_ids=[],
                    max_similarity_score=max_score,
                    correlation_type="temporal_and_semantic",
                )

            # Persist current finding point into Qdrant for future correlations
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, finding.finding_id))
            payload = {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "created_at": current_created.isoformat(),
                "cluster_id": result.cluster_id,
            }

            await client.upsert(
                collection_name=self.collection_name,
                points=[
                    qmodels.PointStruct(
                        id=point_id,
                        vector=vector,
                        payload=payload,
                    )
                ],
            )

            return result

        except Exception as e:  # noqa: BLE001
            logger.warning("Correlation error during Qdrant operations: %s", e)
            return CorrelationResult(
                correlation_status="failed",
                error_type="qdrant_failed",
                max_similarity_score=0.0,
                related_finding_ids=[],
            )
