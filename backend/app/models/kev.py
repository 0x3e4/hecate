from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class CisaKevEntry(BaseModel):
    cve_id: str = Field(alias="cveID")
    vendor_project: str | None = Field(default=None, alias="vendorProject")
    product: str | None = None
    vulnerability_name: str | None = Field(default=None, alias="vulnerabilityName")
    date_added: date | None = Field(default=None, alias="dateAdded")
    short_description: str | None = Field(default=None, alias="shortDescription")
    required_action: str | None = Field(default=None, alias="requiredAction")
    due_date: date | None = Field(default=None, alias="dueDate")
    known_ransomware_campaign_use: str | None = Field(default=None, alias="knownRansomwareCampaignUse")
    notes: str | None = None
    cwes: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _normalize(self) -> "CisaKevEntry":
        if self.cve_id:
            self.cve_id = self.cve_id.strip().upper()
        if not isinstance(self.cwes, list):
            self.cwes = []
        else:
            self.cwes = [cwe for cwe in self.cwes if isinstance(cwe, str)]
        return self


class CisaKevCatalog(BaseModel):
    title: str | None = None
    catalog_version: str | None = Field(default=None, alias="catalogVersion")
    date_released: datetime | None = Field(default=None, alias="dateReleased")
    count: int | None = None
    vulnerabilities: list[CisaKevEntry] = Field(default_factory=list)

    model_config = {"populate_by_name": True}
