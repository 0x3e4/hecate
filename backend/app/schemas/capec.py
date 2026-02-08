from pydantic import BaseModel, Field


class CAPECInfo(BaseModel):
    """CAPEC information with title and description."""

    id: str = Field(description="CAPEC identifier (e.g., 'CAPEC-66')")
    name: str = Field(description="CAPEC name/title")
    description: str = Field(description="Brief description of the attack pattern")
    severity: str | None = Field(default=None, description="Typical severity (High, Medium, Low)")
    likelihood: str | None = Field(default=None, description="Likelihood of attack (High, Medium, Low)")
    abstraction: str | None = Field(default=None, description="Abstraction level (Standard, Detailed)")

    model_config = {"populate_by_name": True}


class CAPECFromCWEsRequest(BaseModel):
    """Request to resolve CWE IDs to related CAPEC attack patterns."""

    cwe_ids: list[str] = Field(
        alias="cweIds",
        serialization_alias="cweIds",
        description="List of CWE identifiers to resolve to CAPEC patterns",
    )

    model_config = {"populate_by_name": True}


class CAPECFromCWEsResponse(BaseModel):
    """Response containing CAPEC information resolved from CWE IDs."""

    capecs: dict[str, CAPECInfo] = Field(
        description="Mapping of normalized CAPEC IDs to their information"
    )

    model_config = {"populate_by_name": True}


class CAPECBulkRequest(BaseModel):
    """Request to fetch multiple CAPEC descriptions."""

    capec_ids: list[str] = Field(
        alias="capecIds",
        serialization_alias="capecIds",
        description="List of CAPEC identifiers to fetch",
    )

    model_config = {"populate_by_name": True}


class CAPECBulkResponse(BaseModel):
    """Response containing CAPEC information for multiple IDs."""

    capecs: dict[str, CAPECInfo] = Field(
        description="Mapping of normalized CAPEC IDs to their information"
    )

    model_config = {"populate_by_name": True}
