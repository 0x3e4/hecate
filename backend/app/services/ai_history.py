"""Earlier AI analyses that a new one builds on (see ``format_previous_analyses_block``)."""
from __future__ import annotations

from typing import Any

import structlog
from bson import ObjectId

from app.services.ai_service import PREVIOUS_ANALYSES_MAX

log = structlog.get_logger()


def _short_sha(value: Any) -> str | None:
    return value[:12] if isinstance(value, str) and value else None


async def previous_scan_analyses(scan_repo: Any, scan_id: str, scan: dict[str, Any]) -> list[dict[str, Any]]:
    """Newest first: this scan's own analyses, then the last one of an earlier scan of the target.

    An earlier scan's analysis carries a ``context`` line (when, which commit or
    image), so the model can tell what the current scan changed. Best effort:
    a failed lookup only means no history.
    """
    own = [a for a in reversed(scan.get("ai_analyses") or []) if isinstance(a, dict)]
    if not own and isinstance(scan.get("ai_analysis"), dict):
        own = [scan["ai_analysis"]]
    result = [dict(a, context="earlier analysis of this same scan") for a in own[:PREVIOUS_ANALYSES_MAX]]
    if len(result) >= PREVIOUS_ANALYSES_MAX:
        return result

    target_id = scan.get("target_id")
    if not isinstance(target_id, str) or not target_id:
        return result
    query: dict[str, Any] = {"target_id": target_id, "ai_analysis": {"$ne": None}}
    if ObjectId.is_valid(scan_id):
        query["_id"] = {"$ne": ObjectId(scan_id)}
    created = scan.get("created_at")
    if created is not None:
        query["created_at"] = {"$lt": created}
    try:
        earlier = await scan_repo.collection.find_one(
            query,
            {"ai_analysis": 1, "created_at": 1, "commit_sha": 1, "image_digest": 1},
            sort=[("created_at", -1)],
        )
    except Exception as exc:  # noqa: BLE001 - history is optional context
        log.warning("ai_history.previous_scan_lookup_failed", scan_id=scan_id, error=str(exc))
        return result
    analysis = (earlier or {}).get("ai_analysis")
    if isinstance(analysis, dict):
        when = earlier.get("created_at")
        ref = _short_sha(earlier.get("commit_sha")) or _short_sha(earlier.get("image_digest"))
        context = "analysis of an earlier scan of this target"
        if when is not None:
            context += f" from {when.isoformat() if hasattr(when, 'isoformat') else when}"
        if ref:
            context += f" ({ref})"
        result.append(dict(analysis, context=context))
    return result


def previous_vulnerability_analyses(vulnerability: Any) -> list[dict[str, Any]] | None:
    """The vulnerability's last stored AI assessment, if any."""
    assessment = getattr(vulnerability, "ai_assessment", None)
    return [assessment] if isinstance(assessment, dict) else None
