"""Write-protection for the REST API.

Two layers, both fail-open when nothing is configured so existing deployments
are unaffected. **Reads are never gated** — only ``POST``/``PUT``/``PATCH``/
``DELETE`` are checked, and several "POST" endpoints are actually reads
(``/vulnerabilities/search``), so the gate is applied per genuine-write route /
per write-only router rather than as a blanket method middleware.

Layer A — global admin gate (``require_admin_write``): a mutating request must
carry ``X-System-Password`` matching ``settings.system_password``. Applied
router-level to write-only routers (inventory, notifications, license policies,
saved searches, sync, backup) and per-route to the non-target AI writes.

Layer B — per-target authorization (the ``require_target_write_*`` dependencies):
a write scoped to one SCA target passes if the global admin password matches
(admin override) **or** the target's own ``write_password_hash`` verifies against
``X-Target-Password``. Applied to the target-scoped routes in
``app/api/v1/scans.py``.
"""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request

from app.core.config import settings
from app.core.passwords import verify_password
from app.services.scan_service import ScanService, get_scan_service

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_ADMIN_HEADER = "X-System-Password"
_TARGET_HEADER = "X-Target-Password"
_AI_HEADER = "X-AI-Analysis-Password"

# Marker on every write-gate 401 so the frontend can tell a genuine write-gate
# rejection apart from other 401s (e.g. a wrong AI/system password typed into a
# page-level unlock dialog) and only then show the global write-password prompt.
_WRITE_AUTH_HEADERS = {"X-Write-Auth-Required": "1"}


def _admin_matches(provided: str | None) -> bool:
    return bool(settings.system_password) and provided == settings.system_password


async def require_admin_write(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> None:
    """Layer A: gate mutating requests behind the global admin password.

    No-op for read methods and when ``SYSTEM_PASSWORD`` is unset (fail-open).
    Safe to attach router-level: read routes pass straight through.
    """
    if request.method not in _MUTATING_METHODS:
        return
    if not settings.system_password:
        return
    if _admin_matches(x_system_password):
        return
    raise HTTPException(
        status_code=401,
        detail="System password required for write operations.",
        headers=_WRITE_AUTH_HEADERS,
    )


def _ai_password_matches(provided: str | None) -> bool:
    return bool(settings.ai_analysis_password) and provided == settings.ai_analysis_password


async def require_ai_write(
    request: Request,
    x_ai_analysis_password: str | None = Header(default=None, alias=_AI_HEADER),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> None:
    """Authorize a non-target AI write (single / batch investigation, attack-path).

    When an AI-analysis password is configured, that password ALONE authorizes
    the write — the global admin gate is intentionally not also required, so the
    UI shows only the AI-password prompt. The mismatch 401 deliberately carries
    NO ``X-Write-Auth-Required`` marker, so the page-level AI dialog handles it
    instead of the global write-password prompt. When no AI password is
    configured, fall back to the global admin gate (the system-password modal).
    """
    if settings.ai_analysis_password:
        if not _ai_password_matches(x_ai_analysis_password):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing AI analysis password.",
            )
        return
    await require_admin_write(request, x_system_password=x_system_password)


async def require_ai_target_write_scan(
    scan_id: str,
    x_ai_analysis_password: str | None = Header(default=None, alias=_AI_HEADER),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Authorize a target-scoped AI write (scan AI analysis / attack chain).

    Same precedence as ``require_ai_write``: the AI password alone authorizes
    when configured; otherwise fall back to the per-target write gate (admin
    override or the target's own write password).
    """
    if settings.ai_analysis_password:
        if not _ai_password_matches(x_ai_analysis_password):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing AI analysis password.",
            )
        return
    await require_target_write_scan(
        scan_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def _authorize_target(
    target_id: str | None,
    *,
    x_system_password: str | None,
    x_target_password: str | None,
    service: ScanService,
) -> None:
    """Authorize a write scoped to a single target (admin override OR target pw)."""
    # Admin override always wins.
    if _admin_matches(x_system_password):
        return

    target = await service.target_repo.get(target_id) if target_id else None
    target_hash = target.get("write_password_hash") if target else None

    if target_hash and verify_password(x_target_password or "", target_hash):
        return

    # Fail-open only when neither the global admin password nor this target's
    # own password is configured.
    if not settings.system_password and not target_hash:
        return

    raise HTTPException(
        status_code=401,
        detail="Write password required for this target.",
        headers=_WRITE_AUTH_HEADERS,
    )


async def _authorize_targets(
    target_ids: set[str],
    *,
    x_system_password: str | None,
    x_target_password: str | None,
    service: ScanService,
) -> None:
    """Authorize a write that may span several targets (finding-id batches)."""
    if _admin_matches(x_system_password):
        return
    # A non-admin caller can only act when the batch resolves to a single target
    # whose password they hold. Empty set → defer to the no-target path.
    if len(target_ids) <= 1:
        single = next(iter(target_ids), None)
        await _authorize_target(
            single,
            x_system_password=x_system_password,
            x_target_password=x_target_password,
            service=service,
        )
        return
    raise HTTPException(
        status_code=401,
        detail="Admin password required: selection spans multiple targets.",
        headers=_WRITE_AUTH_HEADERS,
    )


async def _safe_json(request: Request) -> dict:
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


# --- Per-route dependencies (Layer B) ---------------------------------------


async def resolve_target_id_path(
    target_id: str,
    service: ScanService = Depends(get_scan_service),
) -> str:
    """Canonicalize a ``{target_id:path}`` path param.

    Target ids are URLs stored verbatim, so deep links may arrive
    percent-decoded one level deeper than the stored id, scheme-less, or with
    a trailing slash (see ``ScanService.resolve_target_id``). Falls back to
    the raw value when unresolvable so downstream 404 semantics are unchanged.
    Lives here (not in ``scans.py``) because that module already imports from
    this one; FastAPI's dependency cache runs the resolution once per request
    even when both the auth dep and the route handler declare it.
    """
    resolved = await service.resolve_target_id(target_id)
    return resolved if resolved is not None else target_id


async def require_target_write_path(
    target_id: str = Depends(resolve_target_id_path),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Target id is a path parameter (``/targets/{target_id}``[/check])."""
    await _authorize_target(
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_write_scan(
    scan_id: str,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Resolve the owning target from ``scan_id`` in the path."""
    scan = await service.scan_repo.get(scan_id)
    target_id = scan.get("target_id") if scan else None
    await _authorize_target(
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_write_body_target(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Target id comes from the request body as ``targetId`` (VEX bulk / import)."""
    body = await _safe_json(request)
    target_id = body.get("targetId") or body.get("target_id")
    await _authorize_target(
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_write_finding(
    finding_id: str,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Resolve the owning target from a single ``finding_id`` path parameter."""
    target_ids = await service.finding_repo.get_target_ids_for_findings([finding_id])
    await _authorize_targets(
        target_ids,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_write_body_finding_ids(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Resolve owning target(s) from ``findingIds`` in the body (bulk / dismiss)."""
    body = await _safe_json(request)
    finding_ids = body.get("findingIds") or body.get("finding_ids") or []
    if not isinstance(finding_ids, list):
        finding_ids = []
    target_ids = await service.finding_repo.get_target_ids_for_findings(
        [str(f) for f in finding_ids]
    )
    await _authorize_targets(
        target_ids,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_write_manual_scan(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Derive the target id from a manual-scan body (``target`` + ``type``).

    A brand-new target has no stored password, so creating one falls back to the
    global admin gate (re-scanning an existing protected target accepts its
    password).
    """
    body = await _safe_json(request)
    target = body.get("target")
    target_type = body.get("type")
    target_id = None
    if isinstance(target, str) and isinstance(target_type, str):
        try:
            target_id = service._derive_target_id(target, target_type)
        except Exception:
            target_id = None
    await _authorize_target(
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )
