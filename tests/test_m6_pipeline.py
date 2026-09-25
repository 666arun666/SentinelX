import asyncio
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from sentinelx.agents.models import (
    CorrelationResult,
    EnrichmentResult,
    MitreMapping,
    MitreResult,
)
from sentinelx.agents.supervisor import create_supervisor_graph
from sentinelx.agents.worker import EnrichmentWorker
from sentinelx.core.db import AsyncSessionLocal
from sentinelx.models.db_models import Event, Finding


@pytest.fixture
def sample_finding_and_event():
    uid = str(uuid.uuid4())
    now = datetime.now(UTC)
    finding = Finding(
        finding_id=f"find_{uid}",
        rule_id="auditd_execve_root",
        title="Execution as Root",
        severity="high",
        event_id=f"evt_{uid}",
        status="open",
        created_at=now,
        evidence={"cmd": "whoami"},
    )
    event = Event(
        event_id=f"evt_{uid}",
        event_time=now,
        collected_at=now,
        source="auditd",
        raw_log="type=SYSCALL arch=c000003e syscall=59 success=yes exit=0",
        event_type="process_execution",
        username="root",
    )
    return finding, event


@pytest.mark.asyncio
async def test_m6_graph_both_agents_succeed(sample_finding_and_event):
    finding, event = sample_finding_and_event

    mock_ti_client = AsyncMock()
    mock_mitre_agent = AsyncMock()
    mock_correlation_agent = AsyncMock()

    mock_mitre_agent.map_finding.return_value = MitreResult(
        status="success",
        mappings=[
            MitreMapping(
                tactic_id="TA0004",
                technique_id="T1548",
                tactic_name="Privilege Escalation",
                technique_name="Abuse Elevation Control Mechanism",
            )
        ],
    )
    mock_correlation_agent.correlate_finding.return_value = CorrelationResult(
        correlation_status="correlated",
        cluster_id="cluster-999",
        related_finding_ids=["find_other_1"],
        max_similarity_score=0.92,
    )

    graph = create_supervisor_graph(
        client=mock_ti_client,
        mitre_agent=mock_mitre_agent,
        correlation_agent=mock_correlation_agent,
    )

    initial_state = {
        "finding": finding,
        "event": event,
        "enrichment_result": EnrichmentResult(status="not_attempted"),
        "correlation_result": CorrelationResult(correlation_status="isolated"),
        "mitre_result": MitreResult(status="not_attempted"),
        "ips": [],
        "hashes": [],
        "domains": [],
        "vt_done": True,
        "abuseipdb_done": True,
    }

    result = await graph.ainvoke(initial_state)

    assert result["mitre_result"].status == "success"
    assert len(result["mitre_result"].mappings) == 1
    assert result["correlation_result"].correlation_status == "correlated"
    assert result["correlation_result"].cluster_id == "cluster-999"

    # Verify M3 immutability
    assert finding.severity == "high"
    assert finding.rule_id == "auditd_execve_root"
    assert event.raw_log == "type=SYSCALL arch=c000003e syscall=59 success=yes exit=0"


@pytest.mark.asyncio
async def test_m6_graph_mitre_fails_correlation_succeeds(sample_finding_and_event):
    finding, event = sample_finding_and_event

    mock_ti_client = AsyncMock()
    mock_mitre_agent = AsyncMock()
    mock_correlation_agent = AsyncMock()

    mock_mitre_agent.map_finding.return_value = MitreResult(
        status="failed", error_type="timeout"
    )
    mock_correlation_agent.correlate_finding.return_value = CorrelationResult(
        correlation_status="isolated", max_similarity_score=0.3
    )

    graph = create_supervisor_graph(
        client=mock_ti_client,
        mitre_agent=mock_mitre_agent,
        correlation_agent=mock_correlation_agent,
    )

    initial_state = {
        "finding": finding,
        "event": event,
        "enrichment_result": EnrichmentResult(status="not_attempted"),
        "correlation_result": CorrelationResult(correlation_status="isolated"),
        "mitre_result": MitreResult(status="not_attempted"),
        "ips": [],
        "hashes": [],
        "domains": [],
        "vt_done": True,
        "abuseipdb_done": True,
    }

    result = await graph.ainvoke(initial_state)

    assert result["mitre_result"].status == "failed"
    assert result["correlation_result"].correlation_status == "isolated"


@pytest.mark.asyncio
async def test_m6_worker_real_postgres_persistence():
    uid = str(uuid.uuid4())
    now = datetime.now(UTC)

    event = Event(
        event_id=f"evt_{uid}",
        event_time=now,
        collected_at=now,
        source="syslog",
        raw_log="sudo: test execution",
        severity="low",
    )
    finding = Finding(
        finding_id=f"find_{uid}",
        rule_id="test_rule",
        title="Test Title",
        severity="medium",
        event_id=f"evt_{uid}",
        status="open",
        created_at=now,
        evidence={"test": 123},
    )

    async with AsyncSessionLocal() as session:
        session.add(event)
        session.add(finding)
        await session.commit()

    queue: asyncio.Queue[str] = asyncio.Queue()
    worker = EnrichmentWorker(queue)

    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    worker.ti_client = AsyncMock()
    worker.mitre_agent = AsyncMock()
    worker.correlation_agent = AsyncMock()

    worker.mitre_agent.map_finding.return_value = MitreResult(
        status="success",
        mappings=[
            MitreMapping(
                tactic_id="TA0002",
                technique_id="T1059",
                tactic_name="Execution",
                technique_name="Command and Scripting Interpreter",
            )
        ],
    )
    worker.correlation_agent.correlate_finding.return_value = CorrelationResult(
        correlation_status="isolated",
        max_similarity_score=0.45,
    )

    # Process finding through worker
    await worker._process_finding(f"find_{uid}")

    # Read back from real PostgreSQL and verify M6 columns
    async with AsyncSessionLocal() as session:
        stmt = select(Finding).where(Finding.finding_id == f"find_{uid}")
        db_finding = (await session.execute(stmt)).scalar_one()

        # Authoritative M3 fields preserved
        assert db_finding.severity == "medium"
        assert db_finding.rule_id == "test_rule"
        assert db_finding.title == "Test Title"

        # M6 columns successfully populated
        assert db_finding.mitre_tags is not None
        assert db_finding.mitre_tags["status"] == "success"
        assert len(db_finding.mitre_tags["mappings"]) == 1
        assert db_finding.mitre_tags["mappings"][0]["technique_id"] == "T1059"

        assert db_finding.correlations is not None
        assert db_finding.correlations["correlation_status"] == "isolated"
        assert db_finding.correlations["max_similarity_score"] == 0.45


@pytest.mark.asyncio
async def test_qdrant_live_integration():
    """Verify live Qdrant container connection and collection operations."""
    from qdrant_client.http import models as qmodels

    from sentinelx.agents.correlation import CorrelationAgent

    agent = CorrelationAgent(collection_name="test_verify_collection")
    client = await agent.get_qdrant_client()
    try:
        test_col = "test_verify_collection"
        await agent.ensure_collection_exists()

        # Upsert test point
        await client.upsert(
            collection_name=test_col,
            points=[
                qmodels.PointStruct(
                    id=1, vector=[0.1] * 1536, payload={"label": "test"}
                )
            ],
        )

        # Search test point using agent.search_points
        hits = await agent.search_points(vector=[0.1] * 1536, limit=1)
        assert len(hits) == 1
        assert hits[0].payload["label"] == "test"

        # Cleanup test collection
        await client.delete_collection(collection_name=test_col)

    except Exception as e:  # noqa: BLE001
        pytest.fail(f"Live Qdrant integration failed: {e}")
