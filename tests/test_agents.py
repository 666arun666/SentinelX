from unittest.mock import AsyncMock, patch

import pytest
from httpx import TimeoutException

from sentinelx.agents.models import EnrichmentResult, ProviderStatus
from sentinelx.agents.supervisor import (
    GraphState,
    merge_node,
    route_providers,
)
from sentinelx.agents.threat_intel import ThreatIntelClient
from sentinelx.agents.utils import extract_domains, extract_hashes, extract_ipv4
from sentinelx.models.db_models import Event, Finding


def test_extract_ipv4():
    e = Event(source_ip="8.8.8.8", destination_ip="10.0.0.1", raw_log="")
    ips = extract_ipv4(e)
    assert "8.8.8.8" in ips
    assert "10.0.0.1" not in ips  # Private


def test_extract_hashes():
    e = Event(
        indicators={"hash": "d41d8cd98f00b204e9800998ecf8427e", "invalid": "123"},
        raw_log="",
    )
    hashes = extract_hashes(e)
    assert hashes == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_extract_domains():
    e = Event(
        indicators={"domain": "example.com", "other": "not.a.domain.com!"}, raw_log=""
    )
    domains = extract_domains(e)
    assert domains == ["example.com"]


def test_route_providers():
    # Only IP
    state = GraphState(
        ips=["8.8.8.8"],
        hashes=[],
        domains=[],
        abuseipdb_done=False,
        vt_done=False,
        finding=Finding(),
        event=Event(),
        enrichment_result=EnrichmentResult(status="in_progress"),
    )
    assert route_providers(state) == ["abuseipdb_node"]

    # Only Hash
    state["ips"] = []
    state["hashes"] = ["hash1"]
    assert route_providers(state) == ["vt_node"]

    # Both
    state["ips"] = ["8.8.8.8"]
    routes = route_providers(state)
    assert "vt_node" in routes
    assert "abuseipdb_node" in routes

    # Done
    state["vt_done"] = True
    state["abuseipdb_done"] = True
    assert route_providers(state) == "ti_merge_node"


@pytest.mark.asyncio
async def test_threat_intel_client_redis_cache():
    mock_redis = AsyncMock()
    mock_redis.get.return_value = '{"cached": true}'

    client = ThreatIntelClient(mock_redis)
    client.abuseipdb_key = "test"

    # Should hit cache
    res = await client.check_abuseipdb("8.8.8.8")
    assert res.status == "success"
    assert res.data == {"cached": True}
    mock_redis.get.assert_called_once_with("abuseipdb:ipv4:8.8.8.8")


@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_threat_intel_client_vt_timeout(mock_get):
    mock_get.side_effect = TimeoutException("timeout")
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None

    client = ThreatIntelClient(mock_redis)
    client.vt_key = "test"

    res = await client.check_virustotal_hash("hash1")
    assert res.status == "failed"
    assert res.error_type == "timeout"


@pytest.mark.asyncio
async def test_merge_node():
    res = EnrichmentResult(status="in_progress")
    res.providers["vt"] = ProviderStatus(status="success")
    res.providers["abuse"] = ProviderStatus(status="failed")

    state = GraphState(
        enrichment_result=res,
        finding=Finding(),
        event=Event(),
        ips=[],
        hashes=[],
        domains=[],
        vt_done=True,
        abuseipdb_done=True,
    )

    out = await merge_node(state)
    assert out["enrichment_result"].status == "partial"

    # All success
    res.providers["abuse"].status = "success"
    out = await merge_node(state)
    assert out["enrichment_result"].status == "enriched"

    # All failed
    res.providers["vt"].status = "failed"
    res.providers["abuse"].status = "failed"
    out = await merge_node(state)
    assert out["enrichment_result"].status == "failed"
