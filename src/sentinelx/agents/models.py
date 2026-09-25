from typing import Any, Literal

from pydantic import BaseModel, Field


class ProviderStatus(BaseModel):
    status: Literal["success", "failed", "not_attempted", "in_progress"]
    error_type: str | None = None
    data: dict[str, Any] | None = None


class EnrichmentResult(BaseModel):
    status: Literal["not_attempted", "in_progress", "enriched", "partial", "failed"]
    providers: dict[str, ProviderStatus] = Field(default_factory=dict)


class MitreMapping(BaseModel):
    tactic_id: str
    technique_id: str
    tactic_name: str | None = None
    technique_name: str | None = None
    confidence: float | None = None


class MitreResult(BaseModel):
    status: Literal[
        "success", "partial", "failed", "validation_failed", "not_attempted"
    ]
    mappings: list[MitreMapping] = Field(default_factory=list)
    raw_llm_response: str | None = None
    error_type: str | None = None


class CorrelationResult(BaseModel):
    correlation_status: Literal["correlated", "isolated", "failed"]
    cluster_id: str | None = None
    related_finding_ids: list[str] = Field(default_factory=list)
    max_similarity_score: float = 0.0
    correlation_type: str = "temporal_and_semantic"
    error_type: str | None = None
