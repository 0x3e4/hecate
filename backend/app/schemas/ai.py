from typing import Literal

from pydantic import BaseModel, Field

AIProviderLiteral = Literal["openai", "anthropic", "gemini"]


class AIProviderInfo(BaseModel):
    id: AIProviderLiteral
    label: str


class AIInvestigationRequest(BaseModel):
    provider: AIProviderLiteral
    language: str | None = None
    additional_context: str | None = Field(
        default=None,
        alias="additionalContext",
        description="Optional additional context or information to consider in the analysis",
    )

    model_config = {"populate_by_name": True}


class AIInvestigationResponse(BaseModel):
    provider: AIProviderLiteral
    language: str
    summary: str
    generated_at: str = Field(alias="generatedAt", serialization_alias="generatedAt")

    model_config = {"populate_by_name": True}


class AIBatchInvestigationRequest(BaseModel):
    vulnerability_ids: list[str] = Field(
        min_length=1,
        max_length=10,
        alias="vulnerabilityIds",
        description="List of vulnerability identifiers to analyze together (1-10)",
    )
    provider: AIProviderLiteral
    language: str | None = None
    additional_context: str | None = Field(
        default=None,
        alias="additionalContext",
        description="Optional additional context or information to consider in the analysis",
    )

    model_config = {"populate_by_name": True}


class AIBatchInvestigationResponse(BaseModel):
    provider: AIProviderLiteral
    language: str
    summary: str
    individual_summaries: dict[str, str] = Field(
        alias="individualSummaries",
        serialization_alias="individualSummaries",
        description="Per-vulnerability analysis keyed by vulnerability ID",
    )
    generated_at: str = Field(alias="generatedAt", serialization_alias="generatedAt")
    vulnerability_count: int = Field(alias="vulnerabilityCount", serialization_alias="vulnerabilityCount")

    model_config = {"populate_by_name": True}


class BatchAnalysisReference(BaseModel):
    """Reference to a batch analysis that includes this vulnerability."""
    batch_id: str = Field(alias="batchId", serialization_alias="batchId")
    provider: AIProviderLiteral
    timestamp: str
    summary_excerpt: str = Field(
        alias="summaryExcerpt",
        serialization_alias="summaryExcerpt",
        description="First 200 characters of the individual analysis",
    )

    model_config = {"populate_by_name": True}
