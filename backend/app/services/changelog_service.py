from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Depends
import structlog

from app.core.config import settings
from app.db.mongo import get_database
from app.schemas.changelog import (
    ChangeHistoryField,
    ChangelogEntry,
    ChangelogResponse,
    LatestChange,
)

log = structlog.get_logger()


# Source-slug → list of `last_change_job` values produced by the corresponding
# pipeline. Mapping the UI's coarse filter ("osv") to the exact job names used
# at write time lets the changelog query stay on `$in` against an indexed
# field — anchored regex (``^osv_``) defeats the compound
# `(last_change_job, last_change_at)` index and a 50-row page took 20 s.
# Keep this in sync with the writers that call ``_stamp_last_change_job``.
_SOURCE_TO_JOB_NAMES: dict[str, list[str]] = {
    "osv": ["osv_sync", "osv_initial_sync"],
    "nvd": ["nvd_sync", "nvd_initial_sync"],
    "euvd": ["euvd_ingestion", "euvd_initial_sync"],
    "ghsa": ["ghsa_sync", "ghsa_initial_sync"],
    "circl": ["circl_sync"],
    "kev": ["kev_sync", "kev_initial_sync"],
    "deps_dev": ["deps_dev_enrichment"],
    "deps.dev": ["deps_dev_enrichment"],
    "depsdev": ["deps_dev_enrichment"],
    "manual": ["manual_refresh"],
    "manual_refresh": ["manual_refresh"],
}


class ChangelogService:
    """Service for retrieving recent vulnerability changes."""

    async def get_recent_changes(
        self,
        limit: int = 50,
        offset: int = 0,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        source: str | None = None,
    ) -> ChangelogResponse:
        """
        Retrieve recent vulnerability changes (creations and updates).

        Returns vulnerabilities sorted by their most recent timestamp (ingested_at or modified).
        Optionally filtered by a datetime range on ``ingested_at`` and/or source name.
        """
        try:
            db = await get_database()
            collection = db[settings.mongo_vulnerabilities_collection]

            # Build optional filters
            query_filter: dict = {}
            if from_date or to_date:
                # Filter on last_change_at (denormalized, indexed) so the date
                # range reflects when changes actually happened.
                date_constraint: dict = {}
                if from_date:
                    date_constraint["$gte"] = from_date
                if to_date:
                    date_constraint["$lte"] = to_date
                query_filter["last_change_at"] = date_constraint
            if source:
                # Map the source slug to the exact `last_change_job` values
                # the pipelines write. ``$in`` against the indexed
                # ``last_change_job`` field (compound with
                # ``last_change_at -1``) makes filter+sort run in ~50 ms;
                # the previous anchored ``$regex`` query took ~20 s.
                source_lower = source.lower().strip()
                job_names = _SOURCE_TO_JOB_NAMES.get(source_lower)
                if job_names is None:
                    # Unknown source — fall back to a case-sensitive prefix
                    # regex. Slow but never returns wrong data.
                    query_filter["last_change_job"] = {
                        "$regex": f"^{source_lower}_"
                    }
                else:
                    query_filter["last_change_job"] = {"$in": job_names}

            # Only fetch the fields we need to improve performance
            projection = {
                "_id": 1,
                "title": 1,
                "source": 1,
                "ingested_at": 1,
                "last_change_at": 1,
                "modified": 1,
                "cvss.base_score": 1,
                "cvss.severity": 1,
                "change_history": 1,
            }
            cursor = collection.find(query_filter, projection).sort("last_change_at", -1).skip(offset).limit(limit)
            documents = await cursor.to_list(length=limit)

            # Use count_documents when a filter is active for accuracy,
            # otherwise use estimated_document_count for speed.
            if query_filter:
                total = await collection.count_documents(query_filter)
            else:
                total = await collection.estimated_document_count()

            log.info(f"Found {len(documents)} documents, total: {total}")

            entries = []
            for doc in documents:
                try:
                    cvss_data = doc.get("cvss", {}) or {}

                    ingested_at = doc.get("ingested_at")

                    # Derive change_type and timestamp from the latest
                    # change_history entry when available; fall back to
                    # the ingested_at / modified heuristic.
                    change_history = doc.get("change_history", [])
                    latest_ch = None
                    if change_history and isinstance(change_history, list):
                        sorted_ch = sorted(
                            [h for h in change_history if isinstance(h, dict) and h.get("changed_at")],
                            key=lambda x: x["changed_at"],
                            reverse=True,
                        )
                        if sorted_ch:
                            latest_ch = sorted_ch[0]

                    # Use last_change_at (matches the date filter), fall back to ingested_at
                    last_change_at = doc.get("last_change_at")
                    timestamp = last_change_at if isinstance(last_change_at, datetime) else (ingested_at if ingested_at else datetime.now(UTC))

                    if latest_ch:
                        ch_type = latest_ch.get("change_type", "")
                        change_type = "created" if ch_type == "create" else "updated"
                    else:
                        change_type = "created"
                        modified = doc.get("modified")
                        if modified and ingested_at:
                            if isinstance(modified, datetime) and isinstance(ingested_at, datetime):
                                if abs((modified - ingested_at).total_seconds()) > 3600:
                                    change_type = "updated"

                    # Ensure timestamp is a datetime object
                    if not isinstance(timestamp, datetime):
                        log.warning(f"Timestamp is not datetime: {type(timestamp)}, converting")
                        timestamp = datetime.now(UTC)

                    # Build latest_change from the entry we already resolved above
                    latest_change = None
                    if latest_ch:
                        fields_data = latest_ch.get("fields", [])
                        fields = []
                        if isinstance(fields_data, list):
                            for field in fields_data:
                                if isinstance(field, dict):
                                    fields.append(
                                        ChangeHistoryField(
                                            name=str(field.get("name", "")),
                                            previous=field.get("previous"),
                                            current=field.get("current"),
                                        )
                                    )

                        latest_change = LatestChange(
                            changed_at=latest_ch["changed_at"].isoformat() if isinstance(latest_ch["changed_at"], datetime) else str(latest_ch["changed_at"]),
                            change_type=str(latest_ch.get("change_type", "")),
                            job_name=str(latest_ch.get("job_name", "")),
                            job_label=str(latest_ch.get("job_label")) if latest_ch.get("job_label") else None,
                            fields=fields,
                        )

                    entry = ChangelogEntry(
                        vuln_id=str(doc.get("_id", "")),
                        title=str(doc.get("title", "")),
                        source=str(doc.get("source", "")),
                        change_type=change_type,
                        timestamp=timestamp,
                        cvss_score=cvss_data.get("base_score") if isinstance(cvss_data, dict) else None,
                        severity=cvss_data.get("severity") if isinstance(cvss_data, dict) else None,
                        latest_change=latest_change,
                    )
                    entries.append(entry)
                    log.debug(f"Successfully added entry for {doc.get('_id')}")
                except Exception as e:
                    log.warning("Failed to process changelog entry", error=str(e), doc_id=doc.get("_id"))
                    import traceback
                    log.warning(f"Traceback: {traceback.format_exc()}")
                    continue

            log.info(f"Returning {len(entries)} entries")
            return ChangelogResponse(entries=entries, total=total)
        except Exception as e:
            log.error("Failed to retrieve changelog", error=str(e))
            import traceback
            log.error(f"Traceback: {traceback.format_exc()}")
            return ChangelogResponse(entries=[], total=0)


def get_changelog_service() -> ChangelogService:
    """Dependency injection for ChangelogService."""
    return ChangelogService()
