"""Release markers on scans: "this completed scan is what we shipped as 1.4.2".

The EU Cyber Resilience Act asks a manufacturer to keep the SBOM and the
vulnerability handling of every release for years. Hecate never deletes scans
on its own (no retention job, no TTL index: scans, findings and SBOM rows only
go when an admin deletes a scan or a whole target), so a marker is enough to
find a release's evidence again; deleting a single release scan is refused
until the marker is removed.

The marker lives on the scan document as ``release: {label, note, marked_at}``.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from bson import ObjectId
from pymongo.errors import PyMongoError

log = structlog.get_logger()

MAX_LABEL_LENGTH = 64
MAX_NOTE_LENGTH = 500
MAX_RELEASES_LISTED = 500


class ReleaseError(ValueError):
    """A marker that cannot be set. ``status`` is the HTTP status to answer with."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def clean_release_label(label: Any) -> str:
    if not isinstance(label, str) or not label.strip():
        raise ReleaseError("A release needs a version label.")
    value = " ".join(label.split())
    if len(value) > MAX_LABEL_LENGTH:
        raise ReleaseError(f"The release label is longer than {MAX_LABEL_LENGTH} characters.")
    return value


def clean_release_note(note: Any) -> str | None:
    if note is None:
        return None
    if not isinstance(note, str):
        raise ReleaseError("The release note must be text.")
    value = note.strip()
    if not value:
        return None
    if len(value) > MAX_NOTE_LENGTH:
        raise ReleaseError(f"The release note is longer than {MAX_NOTE_LENGTH} characters.")
    # Control characters other than newlines have no place in a note.
    return "".join(c for c in value if c in "\n\t" or ord(c) >= 32)


async def mark_release(scan_repo: Any, scan_id: str, label: Any, note: Any = None) -> dict[str, Any]:
    """Mark a completed scan as a release; returns the updated scan.

    A label is unique per target: two scans called "1.4.2" would make the
    release list ambiguous.
    """
    clean_label = clean_release_label(label)
    clean_note = clean_release_note(note)
    scan = await scan_repo.get(scan_id)
    if not scan:
        raise ReleaseError("Scan not found", status=404)
    if scan.get("status") != "completed":
        raise ReleaseError("Only a completed scan can be marked as a release.", status=409)
    target_id = scan.get("target_id")
    try:
        clash = await scan_repo.collection.find_one(
            {
                "target_id": target_id,
                "release.label": clean_label,
                "_id": {"$ne": ObjectId(scan_id)},
            },
            {"_id": 1},
        )
    except PyMongoError as exc:
        log.warning("scan_release.lookup_failed", scan_id=scan_id, error=str(exc))
        raise ReleaseError("The release could not be saved.", status=503) from exc
    if clash:
        raise ReleaseError(
            f"Another scan of this target is already release {clean_label}.", status=409,
        )
    previous = scan.get("release") or {}
    release = {
        "label": clean_label,
        "note": clean_note,
        # Renaming keeps the original date: the release happened then.
        "marked_at": previous.get("marked_at") or datetime.now(tz=UTC),
    }
    await scan_repo.update_fields(scan_id, {"release": release})
    scan["release"] = release
    log.info("scan_release.marked", scan_id=scan_id, target_id=target_id, label=clean_label)
    return scan


async def clear_release(scan_repo: Any, scan_id: str) -> dict[str, Any]:
    scan = await scan_repo.get(scan_id)
    if not scan:
        raise ReleaseError("Scan not found", status=404)
    if scan.get("release"):
        try:
            await scan_repo.collection.update_one({"_id": ObjectId(scan_id)}, {"$unset": {"release": ""}})
        except PyMongoError as exc:
            log.warning("scan_release.clear_failed", scan_id=scan_id, error=str(exc))
            raise ReleaseError("The release could not be removed.", status=503) from exc
        log.info("scan_release.cleared", scan_id=scan_id, label=(scan.get("release") or {}).get("label"))
    scan.pop("release", None)
    return scan


async def list_releases(scan_repo: Any, target_id: str) -> list[dict[str, Any]]:
    """Release scans of a target, newest marker first (served by the target_id index)."""
    try:
        cursor = (
            scan_repo.collection.find(
                {"target_id": target_id, "release.label": {"$exists": True}},
                {
                    "release": 1, "status": 1, "started_at": 1, "finished_at": 1,
                    "commit_sha": 1, "image_ref": 1, "summary": 1, "target_id": 1,
                    "branch": 1, "sbom_component_count": 1,
                },
            )
            .sort("release.marked_at", -1)
            .limit(MAX_RELEASES_LISTED)
        )
        out: list[dict[str, Any]] = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            out.append(doc)
        return out
    except PyMongoError as exc:
        log.warning("scan_release.list_failed", target_id=target_id, error=str(exc))
        return []
