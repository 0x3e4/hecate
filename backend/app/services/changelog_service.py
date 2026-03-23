from __future__ import annotations

from datetime import datetime, timedelta
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
                date_constraint: dict = {}
                if from_date:
                    date_constraint["$gte"] = from_date
                if to_date:
                    date_constraint["$lte"] = to_date
                query_filter["ingested_at"] = date_constraint
            if source:
                # Filter by the *most recent* change_history entry's job_name
                # (not the vulnerability's primary source) so enrichment-only
                # jobs like KEV and CIRCL show their changes correctly, and
                # e.g. NVD filter doesn't include entries last touched by CIRCL.
                source_lower = source.lower()
                query_filter["$expr"] = {
                    "$let": {
                        "vars": {
                            "last": {"$arrayElemAt": [{"$ifNull": ["$change_history", []]}, -1]},
                        },
                        "in": {
                            "$regexMatch": {
                                "input": {"$ifNull": [{"$getField": {"field": "job_name", "input": "$$last"}}, ""]},
                                "regex": f"^{source_lower}_",
                                "options": "i",
                            }
                        },
                    }
                }

            # Only fetch the fields we need to improve performance
            projection = {
                "_id": 1,
                "title": 1,
                "source": 1,
                "ingested_at": 1,
                "modified": 1,
                "cvss.base_score": 1,
                "cvss.severity": 1,
                "change_history": 1,
            }
            cursor = collection.find(query_filter, projection).sort("ingested_at", -1).skip(offset).limit(limit)
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

                    # Determine change type based on modified vs ingested_at
                    ingested_at = doc.get("ingested_at")
                    modified = doc.get("modified")

                    log.debug(f"Processing doc {doc.get('_id')}: ingested_at={ingested_at}, modified={modified}")

                    # If modified exists and is significantly different from ingested_at, it's an update
                    change_type = "created"
                    timestamp = ingested_at if ingested_at else datetime.now()

                    if modified and ingested_at:
                        # If modified is more than 1 hour after ingested_at, consider it an update
                        if isinstance(modified, datetime) and isinstance(ingested_at, datetime):
                            time_diff = (modified - ingested_at).total_seconds()
                            if abs(time_diff) > 3600:  # More than 1 hour difference
                                change_type = "updated"
                                # Keep timestamp as ingested_at (don't change to modified)

                    # Ensure timestamp is a datetime object
                    if not isinstance(timestamp, datetime):
                        log.warning(f"Timestamp is not datetime: {type(timestamp)}, converting")
                        timestamp = datetime.now()

                    # Get latest change history entry
                    latest_change = None
                    change_history = doc.get("change_history", [])
                    if change_history and isinstance(change_history, list) and len(change_history) > 0:
                        # Sort by changed_at to get the most recent
                        sorted_history = sorted(
                            [h for h in change_history if h.get("changed_at")],
                            key=lambda x: x.get("changed_at"),
                            reverse=True
                        )
                        if sorted_history:
                            latest = sorted_history[0]
                            fields_data = latest.get("fields", [])
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
                                changed_at=latest.get("changed_at").isoformat() if isinstance(latest.get("changed_at"), datetime) else str(latest.get("changed_at")),
                                change_type=str(latest.get("change_type", "")),
                                job_name=str(latest.get("job_name", "")),
                                job_label=str(latest.get("job_label")) if latest.get("job_label") else None,
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
