from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError
from pydantic import ValidationError
from dateutil import parser

from app.core.config import settings
from app.db.mongo import get_database
from app.models.kev import CisaKevEntry
from app.models.vulnerability import ExploitationMetadata

log = structlog.get_logger()


class KevRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "KevRepository":
        database = await get_database()
        collection = database[settings.mongo_kev_collection]
        await collection.create_index("cve_id", unique=True)
        return cls(collection)

    async def existing_cve_ids(self) -> set[str]:
        identifiers: set[str] = set()
        try:
            cursor = self.collection.find({}, {"_id": 1})
            async for document in cursor:
                cve = document.get("_id")
                if isinstance(cve, str):
                    identifiers.add(cve)
        except PyMongoError as exc:
            log.warning("kev_repository.fetch_ids_failed", error=str(exc))
        return identifiers

    @staticmethod
    def _as_datetime(value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.astimezone(UTC)
        if isinstance(value, date):
            return datetime.combine(value, datetime.min.time(), tzinfo=UTC)
        if isinstance(value, str):
            try:
                parsed = parser.isoparse(value)
            except (ValueError, TypeError):
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        return None

    async def upsert_entry(
        self,
        entry: CisaKevEntry,
        *,
        catalog_version: str | None,
        date_released: datetime | None,
    ) -> str:
        payload = entry.model_dump(mode="python", by_alias=False)
        payload["_id"] = entry.cve_id
        payload["cve_id"] = entry.cve_id
        payload["catalog_version"] = catalog_version
        payload["date_added"] = self._as_datetime(payload.get("date_added"))
        payload["due_date"] = self._as_datetime(payload.get("due_date"))
        payload["date_released"] = self._as_datetime(date_released)
        if entry.raw:
            payload["raw"] = entry.raw
        try:
            existing = await self.collection.find_one({"_id": entry.cve_id})
        except PyMongoError as exc:
            log.warning("kev_repository.lookup_failed", cve_id=entry.cve_id, error=str(exc))
            existing = None

        try:
            await self.collection.replace_one(
                {"_id": entry.cve_id},
                payload,
                upsert=True,
            )
        except PyMongoError as exc:
            log.warning("kev_repository.upsert_failed", cve_id=entry.cve_id, error=str(exc))
            raise

        return "inserted" if existing is None else "updated"

    async def get_entry(self, cve_id: str) -> dict[str, Any] | None:
        try:
            return await self.collection.find_one({"_id": cve_id})
        except PyMongoError as exc:
            log.warning("kev_repository.get_failed", cve_id=cve_id, error=str(exc))
            return None

    async def load_metadata_map(self) -> dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]]:
        metadata: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]] = {}
        try:
            cursor = self.collection.find({})
            async for document in cursor:
                cve = document.get("_id")
                if not isinstance(cve, str):
                    continue
                payload = {
                    "vendorProject": document.get("vendor_project"),
                    "product": document.get("product"),
                    "vulnerabilityName": document.get("vulnerability_name"),
                    "dateAdded": document.get("date_added") or document.get("dateAdded"),
                    "shortDescription": document.get("short_description") or document.get("shortDescription"),
                    "requiredAction": document.get("required_action") or document.get("requiredAction"),
                    "dueDate": document.get("due_date") or document.get("dueDate"),
                    "knownRansomwareCampaignUse": document.get("known_ransomware_campaign_use")
                    or document.get("knownRansomwareCampaignUse"),
                    "notes": document.get("notes"),
                    "catalogVersion": document.get("catalog_version"),
                    "dateReleased": document.get("date_released") or document.get("dateReleased"),
                }
                try:
                    metadata_model = ExploitationMetadata.model_validate(payload)
                except ValidationError as exc:
                    log.warning("kev_repository.metadata_validation_failed", cve_id=cve, error=str(exc))
                    continue
                raw_entry = document.get("raw") if isinstance(document.get("raw"), dict) else None
                metadata[cve] = (metadata_model, raw_entry)
        except PyMongoError as exc:
            log.warning("kev_repository.metadata_load_failed", error=str(exc))
        return metadata
