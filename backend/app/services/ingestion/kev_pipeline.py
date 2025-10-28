from __future__ import annotations

from datetime import UTC, datetime, date
from typing import Any

import structlog
from dateutil import parser

from app.models.vulnerability import ExploitationMetadata
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.kev_repository import KevRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.ingestion.cisa_client import CisaKevClient
from app.services.ingestion.job_tracker import JobTracker

log = structlog.get_logger()

STATE_KEY = "kev"


class KevPipeline:
    def __init__(
        self,
        *,
        client: CisaKevClient | None = None,
    ) -> None:
        self.client = client or CisaKevClient()

    async def sync(self, *, initial_sync: bool = False) -> dict[str, Any]:
        kev_repository = await KevRepository.create()
        vulnerability_repository = await VulnerabilityRepository.create()
        state_repository = await IngestionStateRepository.create()
        tracker = JobTracker(state_repository)

        job_name = "kev_initial_sync" if initial_sync else "kev_sync"
        label = "CISA KEV Initial Sync" if initial_sync else "CISA KEV Sync"

        ctx = await tracker.start(
            job_name,
            label=label,
            initial_sync=initial_sync,
        )

        inserted_entries = 0
        updated_entries = 0
        unchanged_entries = 0
        applied_updates = 0
        missing_vulnerabilities = 0

        try:
            catalog = await self.client.fetch_catalog()
            if catalog is None:
                await tracker.fail(ctx, "catalog_fetch_failed")
                return {
                    "inserted": inserted_entries,
                    "updated": updated_entries,
                    "unchanged": unchanged_entries,
                    "applied": applied_updates,
                    "pending": missing_vulnerabilities,
                    "initial_sync": initial_sync,
                }

            entries = [entry for entry in catalog.vulnerabilities if entry.cve_id]

            if not entries:
                log.info("kev_pipeline.no_entries")
                await state_repository.update_state(
                    STATE_KEY,
                    {
                        "last_run": datetime.now(tz=UTC),
                        "catalog_version": catalog.catalog_version,
                        "date_released": catalog.date_released,
                        "count": 0,
                        "processed": 0,
                    },
                )
                result = {
                    "inserted": inserted_entries,
                    "updated": updated_entries,
                    "unchanged": unchanged_entries,
                    "applied": applied_updates,
                    "pending": missing_vulnerabilities,
                    "catalog_version": catalog.catalog_version,
                    "initial_sync": initial_sync,
                }
                await tracker.finish(ctx, **result)
                return result

            for entry in entries:
                raw_entry = entry.raw if isinstance(entry.raw, dict) else {}
                fallback_vendor = raw_entry.get("vendorProject")
                fallback_product = raw_entry.get("product")
                fallback_name = raw_entry.get("vulnerabilityName")
                fallback_date_added = raw_entry.get("dateAdded")
                fallback_short = raw_entry.get("shortDescription")
                fallback_action = raw_entry.get("requiredAction")
                fallback_due = raw_entry.get("dueDate")
                fallback_ransom = raw_entry.get("knownRansomwareCampaignUse")
                fallback_notes = raw_entry.get("notes")
                fallback_catalog_version = catalog.catalog_version or raw_entry.get("catalogVersion")
                fallback_date_released = catalog.date_released

                status = await kev_repository.upsert_entry(
                    entry,
                    catalog_version=catalog.catalog_version,
                    date_released=catalog.date_released,
                )
                if status == "inserted":
                    inserted_entries += 1
                elif status == "updated":
                    updated_entries += 1
                else:
                    unchanged_entries += 1

                metadata = ExploitationMetadata(
                    vendor_project=entry.vendor_project or fallback_vendor,
                    product=entry.product or fallback_product,
                    vulnerability_name=entry.vulnerability_name or fallback_name,
                    date_added=entry.date_added or _coerce_date(fallback_date_added),
                    short_description=entry.short_description or fallback_short,
                    required_action=entry.required_action or fallback_action,
                    due_date=entry.due_date or _coerce_date(fallback_due),
                    known_ransomware_campaign_use=entry.known_ransomware_campaign_use or fallback_ransom,
                    notes=entry.notes or fallback_notes,
                    catalog_version=fallback_catalog_version,
                    date_released=fallback_date_released,
                )

                change_context = {
                    "job_name": ctx.name,
                    "job_label": ctx.metadata.get("label"),
                    "metadata": {
                        "pipeline": "CISA KEV",
                        "catalog_version": catalog.catalog_version,
                        "initial_sync": initial_sync,
                    },
                }

                try:
                    update_status = await vulnerability_repository.apply_exploitation_metadata(
                        vuln_id=entry.cve_id,
                        metadata=metadata,
                        raw_entry=raw_entry,
                        change_context=change_context,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "kev_pipeline.apply_failed",
                        cve_id=entry.cve_id,
                        error=str(exc),
                    )
                    missing_vulnerabilities += 1
                    continue

                if update_status == "updated":
                    applied_updates += 1
                elif update_status == "missing":
                    missing_vulnerabilities += 1

            await state_repository.update_state(
                STATE_KEY,
                {
                    "last_run": datetime.now(tz=UTC),
                    "catalog_version": catalog.catalog_version,
                    "date_released": catalog.date_released,
                    "count": catalog.count or len(entries),
                    "processed": len(entries),
                },
            )

            result = {
                "inserted": inserted_entries,
                "updated": updated_entries,
                "unchanged": unchanged_entries,
                "applied": applied_updates,
                "pending": missing_vulnerabilities,
                "catalog_version": catalog.catalog_version,
                "initial_sync": initial_sync,
            }
            await tracker.finish(ctx, **result)
            return result
        except Exception as exc:  # noqa: BLE001
            await tracker.fail(ctx, str(exc))
            raise
        finally:
            await self.client.close()


def _coerce_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = parser.isoparse(value)
        except (ValueError, TypeError):
            return None
        if isinstance(parsed, datetime):
            return parsed.date()
        return None
    return None
