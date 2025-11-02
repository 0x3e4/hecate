from typing import Literal

from pydantic import BaseModel, Field

AIProviderLiteral = Literal["openai", "anthropic", "gemini"]


class AIProviderInfo(BaseModel):
    id: AIProviderLiteral
    label: str


class AIInvestigationRequest(BaseModel):
    provider: AIProviderLiteral
    language: str | None = None

    model_config = {"populate_by_name": True}


class AIInvestigationResponse(BaseModel):
    provider: AIProviderLiteral
    language: str
    summary: str
    generated_at: str = Field(alias="generatedAt", serialization_alias="generatedAt")

    model_config = {"populate_by_name": True}
