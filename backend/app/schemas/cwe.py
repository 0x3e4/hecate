from pydantic import BaseModel, Field


class CWEInfo(BaseModel):
    """CWE information with title and description."""

    id: str = Field(description="CWE identifier (e.g., '79', 'CWE-79')")
    name: str = Field(description="CWE name/title")
    description: str = Field(description="Brief description of the weakness")

    model_config = {"populate_by_name": True}


class CWEBulkRequest(BaseModel):
    """Request to fetch multiple CWE descriptions."""

    cwe_ids: list[str] = Field(
        alias="cweIds",
        serialization_alias="cweIds",
        description="List of CWE identifiers to fetch",
    )

    model_config = {"populate_by_name": True}


class CWEBulkResponse(BaseModel):
    """Response containing CWE information for multiple IDs."""

    cwes: dict[str, CWEInfo] = Field(
        description="Mapping of normalized CWE IDs to their information"
    )

    model_config = {"populate_by_name": True}
