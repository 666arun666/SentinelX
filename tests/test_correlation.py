from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelx.agents.correlation import CorrelationAgent
from sentinelx.models.db_models import Event, Finding


@pytest.fixture
def sample_finding_and_event():
    now = datetime.now(UTC)
    finding = Finding(
        finding_id="find_test_201",
        rule_id="sudo_priv_esc",
        title="Suspicious Sudo Execution",
        severity="medium",
        event_id="evt_test_201",
        status="open",
        created_at=now,
        evidence={"command": "/bin/bash"},
    )
    event = Event(
        event_id="evt_test_201",
        event_time=now,
        collected_at=now,
        source="auth.log",
        raw_log="sudo: pam_unix(sudo:session): session opened for user root",
        event_type="privilege_escalation",
        username="attacker",
        source_ip="10.0.0.5",
    )
    return finding, event


@pytest.mark.asyncio
async def test_correlation_missing_api_key(sample_finding_and_event):
    finding, event = sample_finding_and_event
    agent = CorrelationAgent(openai_key="")
    result = await agent.correlate_finding(finding, event)

    assert result.correlation_status == "isolated"
    assert result.error_type == "missing_api_key"
    assert len(result.related_finding_ids) == 0


@pytest.mark.asyncio
async def test_correlation_embedding_failed(sample_finding_and_event):
    finding, event = sample_finding_and_event
    agent = CorrelationAgent(openai_key="test-key")

    with patch.object(agent, "generate_embedding", AsyncMock(return_value=None)):
        result = await agent.correlate_finding(finding, event)

    assert result.correlation_status == "failed"
    assert result.error_type == "embedding_failed"


@pytest.mark.asyncio
async def test_correlation_qdrant_unavailable(sample_finding_and_event):
    finding, event = sample_finding_and_event
    agent = CorrelationAgent(openai_key="test-key")

    with (
        patch.object(agent, "generate_embedding", AsyncMock(return_value=[0.1] * 1536)),
        patch.object(agent, "ensure_collection_exists", AsyncMock(return_value=False)),
    ):
        result = await agent.correlate_finding(finding, event)

    assert result.correlation_status == "failed"
    assert result.error_type == "qdrant_unavailable"


@pytest.mark.asyncio
async def test_correlation_high_similarity_correlated(sample_finding_and_event):
    finding, event = sample_finding_and_event
    agent = CorrelationAgent(openai_key="test-key")
    agent.similarity_threshold = 0.75
    agent.window_seconds = 3600

    fake_vector = [0.1] * 1536
    hit_time = (finding.created_at - timedelta(minutes=5)).isoformat()

    mock_hit = MagicMock()
    mock_hit.score = 0.88
    mock_hit.payload = {
        "finding_id": "find_prev_001",
        "rule_id": "sudo_priv_esc",
        "created_at": hit_time,
        "cluster_id": "cluster-uuid-123",
    }

    mock_qdrant = AsyncMock()
    mock_qdrant.query_points = AsyncMock(return_value=MagicMock(points=[mock_hit]))
    mock_qdrant.upsert = AsyncMock()

    with (
        patch.object(agent, "generate_embedding", AsyncMock(return_value=fake_vector)),
        patch.object(agent, "ensure_collection_exists", AsyncMock(return_value=True)),
        patch.object(agent, "get_qdrant_client", AsyncMock(return_value=mock_qdrant)),
    ):
        result = await agent.correlate_finding(finding, event)

    assert result.correlation_status == "correlated"
    assert "find_prev_001" in result.related_finding_ids
    assert result.cluster_id == "cluster-uuid-123"
    assert result.max_similarity_score == 0.88
    mock_qdrant.upsert.assert_awaited_once()


@pytest.mark.asyncio
async def test_correlation_low_similarity_isolated(sample_finding_and_event):
    finding, event = sample_finding_and_event
    agent = CorrelationAgent(openai_key="test-key")
    agent.similarity_threshold = 0.75

    fake_vector = [0.1] * 1536
    hit_time = (finding.created_at - timedelta(minutes=5)).isoformat()

    mock_hit = MagicMock()
    mock_hit.score = 0.52  # Below 0.75 threshold
    mock_hit.payload = {
        "finding_id": "find_prev_unrelated",
        "created_at": hit_time,
    }

    mock_qdrant = AsyncMock()
    mock_qdrant.query_points = AsyncMock(return_value=MagicMock(points=[mock_hit]))
    mock_qdrant.upsert = AsyncMock()

    with (
        patch.object(agent, "generate_embedding", AsyncMock(return_value=fake_vector)),
        patch.object(agent, "ensure_collection_exists", AsyncMock(return_value=True)),
        patch.object(agent, "get_qdrant_client", AsyncMock(return_value=mock_qdrant)),
    ):
        result = await agent.correlate_finding(finding, event)

    assert result.correlation_status == "isolated"
    assert len(result.related_finding_ids) == 0
    assert result.cluster_id is None
    assert result.max_similarity_score == 0.52


@pytest.mark.asyncio
async def test_correlation_outside_temporal_window_isolated(sample_finding_and_event):
    finding, event = sample_finding_and_event
    agent = CorrelationAgent(openai_key="test-key")
    agent.similarity_threshold = 0.75
    agent.window_seconds = 3600  # 1 hour window

    fake_vector = [0.1] * 1536
    # 3 hours ago -> outside window
    hit_time = (finding.created_at - timedelta(hours=3)).isoformat()

    mock_hit = MagicMock()
    mock_hit.score = 0.95  # Very high similarity
    mock_hit.payload = {
        "finding_id": "find_prev_old",
        "created_at": hit_time,
    }

    mock_qdrant = AsyncMock()
    mock_qdrant.query_points = AsyncMock(return_value=MagicMock(points=[mock_hit]))
    mock_qdrant.upsert = AsyncMock()

    with (
        patch.object(agent, "generate_embedding", AsyncMock(return_value=fake_vector)),
        patch.object(agent, "ensure_collection_exists", AsyncMock(return_value=True)),
        patch.object(agent, "get_qdrant_client", AsyncMock(return_value=mock_qdrant)),
    ):
        result = await agent.correlate_finding(finding, event)

    # Outside window -> isolated
    assert result.correlation_status == "isolated"
    assert len(result.related_finding_ids) == 0
    assert result.cluster_id is None


@pytest.mark.asyncio
async def test_correlation_exclude_self(sample_finding_and_event):
    finding, event = sample_finding_and_event
    agent = CorrelationAgent(openai_key="test-key")

    fake_vector = [0.1] * 1536
    mock_hit = MagicMock()
    mock_hit.score = 1.0
    mock_hit.payload = {
        "finding_id": finding.finding_id,  # Matches self
        "created_at": finding.created_at.isoformat(),
    }

    mock_qdrant = AsyncMock()
    mock_qdrant.query_points = AsyncMock(return_value=MagicMock(points=[mock_hit]))
    mock_qdrant.upsert = AsyncMock()

    with (
        patch.object(agent, "generate_embedding", AsyncMock(return_value=fake_vector)),
        patch.object(agent, "ensure_collection_exists", AsyncMock(return_value=True)),
        patch.object(agent, "get_qdrant_client", AsyncMock(return_value=mock_qdrant)),
    ):
        result = await agent.correlate_finding(finding, event)

    assert result.correlation_status == "isolated"
    assert len(result.related_finding_ids) == 0
