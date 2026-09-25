from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from sentinelx.agents.correlation import CorrelationAgent
from sentinelx.agents.mitre import MitreMappingAgent
from sentinelx.agents.models import CorrelationResult, EnrichmentResult, MitreResult
from sentinelx.agents.threat_intel import ThreatIntelClient
from sentinelx.agents.utils import extract_domains, extract_hashes, extract_ipv4
from sentinelx.models.db_models import Event, Finding


class GraphState(TypedDict):
    finding: Finding
    event: Event
    enrichment_result: EnrichmentResult
    correlation_result: CorrelationResult
    mitre_result: MitreResult
    ips: list[str]
    hashes: list[str]
    domains: list[str]
    vt_done: bool
    abuseipdb_done: bool


async def extract_indicators_node(state: GraphState):
    """Deterministic indicator extraction."""
    event = state["event"]
    ips = extract_ipv4(event)
    hashes = extract_hashes(event)
    domains = extract_domains(event)

    return {
        "ips": ips,
        "hashes": hashes,
        "domains": domains,
        "vt_done": False,
        "abuseipdb_done": False,
    }


def route_providers(state: GraphState):
    """Route to threat intelligence providers independently."""
    routes = []
    if state["ips"] and not state["abuseipdb_done"]:
        routes.append("abuseipdb_node")
    if (state["hashes"] or state["domains"]) and not state["vt_done"]:
        routes.append("vt_node")

    if not routes:
        return "ti_merge_node"
    return routes


async def vt_node(state: GraphState, client: ThreatIntelClient):
    hashes = state["hashes"]
    domains = state["domains"]
    providers = dict(state["enrichment_result"].providers)

    # Process up to 3 indicators to prevent spam
    for h in hashes[:3]:
        res = await client.check_virustotal_hash(h)
        providers[f"virustotal_hash_{h}"] = res

    for d in domains[:3]:
        res = await client.check_virustotal_domain(d)
        providers[f"virustotal_domain_{d}"] = res

    return {
        "enrichment_result": EnrichmentResult(
            status=state["enrichment_result"].status, providers=providers
        ),
        "vt_done": True,
    }


async def abuseipdb_node(state: GraphState, client: ThreatIntelClient):
    ips = state["ips"]
    providers = dict(state["enrichment_result"].providers)

    for ip in ips[:3]:
        res = await client.check_abuseipdb(ip)
        providers[f"abuseipdb_{ip}"] = res

    return {
        "enrichment_result": EnrichmentResult(
            status=state["enrichment_result"].status, providers=providers
        ),
        "abuseipdb_done": True,
    }


async def ti_merge_node(state: GraphState):
    """Summarize M5 threat intelligence results."""
    res = state["enrichment_result"]
    if not res.providers:
        res.status = "not_attempted"
    else:
        failed = any(p.status == "failed" for p in res.providers.values())
        success = any(p.status == "success" for p in res.providers.values())
        if success and not failed:
            res.status = "enriched"
        elif success and failed:
            res.status = "partial"
        else:
            res.status = "failed"

    return {"enrichment_result": res}


merge_node = ti_merge_node


async def correlation_node(state: GraphState, agent: CorrelationAgent):
    """M6 Correlation Agent node."""
    res = await agent.correlate_finding(
        finding=state["finding"],
        event=state["event"],
        enrichments=state["enrichment_result"].model_dump(),
    )
    return {"correlation_result": res}


async def mitre_node(state: GraphState, agent: MitreMappingAgent):
    """M6 MITRE Mapping Agent node."""
    res = await agent.map_finding(
        finding=state["finding"],
        event=state["event"],
        enrichments=state["enrichment_result"].model_dump(),
    )
    return {"mitre_result": res}


async def deterministic_merge_node(state: GraphState):
    """Deterministic validation and merge node for M5 and M6 results.

    Verifies all results adhere strictly to Pydantic schemas.
    Does NOT modify M3 fields (severity, rule_id, event_id, etc.).
    """
    # Defensive checks on existing state
    ti_res = state.get("enrichment_result") or EnrichmentResult(status="failed")
    corr_res = state.get("correlation_result") or CorrelationResult(
        correlation_status="failed", error_type="missing_result"
    )
    mitre_res = state.get("mitre_result") or MitreResult(
        status="failed", error_type="missing_result"
    )

    return {
        "enrichment_result": ti_res,
        "correlation_result": corr_res,
        "mitre_result": mitre_res,
    }


def create_supervisor_graph(
    client: ThreatIntelClient,
    mitre_agent: MitreMappingAgent | None = None,
    correlation_agent: CorrelationAgent | None = None,
):
    workflow = StateGraph(GraphState)

    m_agent = mitre_agent or MitreMappingAgent()
    c_agent = correlation_agent or CorrelationAgent()

    workflow.add_node("extract", extract_indicators_node)

    async def run_vt(state: GraphState):
        return await vt_node(state, client)

    async def run_abuseipdb(state: GraphState):
        return await abuseipdb_node(state, client)

    async def run_correlation(state: GraphState):
        return await correlation_node(state, c_agent)

    async def run_mitre(state: GraphState):
        return await mitre_node(state, m_agent)

    workflow.add_node("vt_node", run_vt)
    workflow.add_node("abuseipdb_node", run_abuseipdb)
    workflow.add_node("ti_merge_node", ti_merge_node)
    workflow.add_node("correlation_node", run_correlation)
    workflow.add_node("mitre_node", run_mitre)
    workflow.add_node("deterministic_merge_node", deterministic_merge_node)

    # Ingestion flow: extract -> TI routing -> ti_merge_node
    workflow.add_edge(START, "extract")
    workflow.add_conditional_edges(
        "extract",
        route_providers,
        ["vt_node", "abuseipdb_node", "ti_merge_node"],
    )

    workflow.add_edge("vt_node", "ti_merge_node")
    workflow.add_edge("abuseipdb_node", "ti_merge_node")

    # M6 Parallel Branches: ti_merge_node -> correlation_node AND mitre_node
    workflow.add_edge("ti_merge_node", "correlation_node")
    workflow.add_edge("ti_merge_node", "mitre_node")

    # Both converge to deterministic_merge_node
    workflow.add_edge("correlation_node", "deterministic_merge_node")
    workflow.add_edge("mitre_node", "deterministic_merge_node")

    workflow.add_edge("deterministic_merge_node", END)

    return workflow.compile()
