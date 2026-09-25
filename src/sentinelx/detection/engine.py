import asyncio
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy.dialects.postgresql import insert

from sentinelx.core.db import AsyncSessionLocal
from sentinelx.detection.rules import Rule, load_rules
from sentinelx.models.db_models import Finding
from sentinelx.models.event import NormalizedEvent

logger = structlog.get_logger(__name__)


class DetectionEngine:
    def __init__(
        self, rules_dir: str | Path, enrichment_queue: asyncio.Queue[str] | None = None
    ):
        self.rules_dir = Path(rules_dir)
        self.enrichment_queue = enrichment_queue
        self.rules = load_rules(self.rules_dir)
        self.rules_by_source: dict[str, list[Rule]] = {}
        self.all_source_rules: list[Rule] = []

        for rule in self.rules:
            if rule.logsource == "all":
                self.all_source_rules.append(rule)
            else:
                if rule.logsource not in self.rules_by_source:
                    self.rules_by_source[rule.logsource] = []
                self.rules_by_source[rule.logsource].append(rule)

        logger.info("detection_engine_initialized", total_rules=len(self.rules))

    async def evaluate_event(self, event: NormalizedEvent) -> None:
        """
        Evaluate an event against loaded rules deterministically.
        Failure in this method should be isolated and caught by the caller.
        """
        applicable_rules = self.all_source_rules.copy()
        if event.source in self.rules_by_source:
            applicable_rules.extend(self.rules_by_source[event.source])

        event_fields = event.model_dump()

        findings_to_persist = []
        for rule in applicable_rules:
            try:
                is_match, evidence = rule.matches(event_fields)
                if is_match:
                    evidence_payload = {
                        "rule_title": rule.title,
                        "matched_fields": evidence,
                        "raw_log": event.raw_log,
                    }
                    finding_id = self._generate_finding_id(rule.rule_id, event.event_id)
                    findings_to_persist.append(
                        {
                            "finding_id": finding_id,
                            "rule_id": rule.rule_id,
                            "title": rule.title,
                            "severity": rule.severity,
                            "event_id": event.event_id,
                            "status": "open",
                            "created_at": datetime.now(UTC),
                            "evidence": evidence_payload,
                        }
                    )
                    logger.info(
                        "detection_alert",
                        rule_id=rule.rule_id,
                        title=rule.title,
                        event_id=event.event_id,
                    )
            except Exception as e:  # noqa: BLE001
                # Rule evaluation failure isolation
                logger.error(
                    "rule_evaluation_failed", rule_id=rule.rule_id, error=str(e)
                )

        if findings_to_persist:
            await self._persist_findings(findings_to_persist)

    def _generate_finding_id(self, rule_id: str, event_id: str) -> str:
        """Deterministic finding deduplication ID."""
        payload = f"{rule_id}:{event_id}".encode()
        return hashlib.sha256(payload).hexdigest()

    async def _persist_findings(self, findings: list[dict[str, Any]]) -> None:
        """Persist findings idempotently."""
        try:
            async with AsyncSessionLocal() as session:
                stmt = insert(Finding).values(findings)
                stmt = stmt.on_conflict_do_nothing(index_elements=["finding_id"])
                await session.execute(stmt)
                await session.commit()
                logger.debug("findings_persisted", count=len(findings))

                if self.enrichment_queue:
                    for f in findings:
                        try:
                            self.enrichment_queue.put_nowait(f["finding_id"])
                        except asyncio.QueueFull:
                            logger.warning(
                                "enrichment_queue_full", finding_id=f["finding_id"]
                            )
        except Exception as e:  # noqa: BLE001
            logger.error("findings_persistence_failed", error=str(e))
            # Must be retryable/observable
            raise RuntimeError(f"Database error during finding persistence: {e}")
