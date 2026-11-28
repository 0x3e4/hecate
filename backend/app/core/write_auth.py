"""Write-protection for the REST API.

Two layers, both fail-open when nothing is configured so existing deployments
are unaffected. **Reads are never gated** — only ``POST``/``PUT``/``PATCH``/
``DELETE`` are checked, and several "POST" endpoints are actually reads
(``/vulnerabilities/search``), so the gate is applied per genuine-write route /
per write-only router rather than as a blanket method middleware.

API tokens (``X-API-Key``) sit beside the two layers: a token carries scopes and
opens exactly the routes that ask for one of them. Managing tokens is the one
fail-closed gate here, because with no system password anyone could mint one.

Layer A — global admin gate (``require_admin_write``): a mutating request must
carry ``X-System-Password`` matching ``settings.system_password``. Applied
router-level to write-only routers (inventory, notifications, license policies,
saved searches, sync, backup) and per-route to the non-target AI writes.

Layer B — per-target authorization (the ``require_target_write_*`` dependencies):
a write scoped to one SCA target passes if the global admin password matches
(admin override) **or** the target's own ``write_password_hash`` verifies against
``X-Target-Password``. Applied to the target-scoped routes in
``app/api/v1/scans.py``.

OIDC roles sit in front of both layers (``app/core/auth_context.py``): a
signed-in ``admin`` passes every gate here, an ``editor`` passes the target
gates and the editor gates (AI fallback, refresh, inventory, saved searches,
creating targets), a ``viewer`` passes none. The password headers are still
checked after the role, so scripts and installs without OIDC are unaffected.
With OIDC configured the gates are no longer fail-open for anonymous callers:
the sign-in is what protects them then. A signed-in user whose role is too low
gets a 403 (``X-Auth-Role-Required``), never a password prompt.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import Depends, Header, Query, HTTPException, Request

from app.core.auth_context import (
    SessionUser,
    current_user,
    login_required_error,
    note_credential,
    role_error,
    with_login_hint,
)
from app.core.auth_throttle import (
    AI_SECRET,
    API_KEY_SECRET,
    SYSTEM_SECRET,
    enforce_auth_throttle,
    record_auth_result,
)
from app.core.config import settings
from app.core.passwords import secret_equals, verify_password
from app.schemas.api_token import SCOPE_INVENTORY_REPORT, SCOPE_INVENTORY_SYNC, SCOPE_SBOM_IMPORT, SCOPE_SCAN_SUBMIT
from app.services.api_token_service import get_api_token_service, looks_like_token
from app.services.scan_service import resolve_sbom_import_target, ScanService, get_scan_service

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_ADMIN_HEADER = "X-System-Password"
_TARGET_HEADER = "X-Target-Password"
_AI_HEADER = "X-AI-Analysis-Password"

# Marker on every write-gate 401 so the frontend can tell a genuine write-gate
# rejection apart from other 401s (e.g. a wrong AI/system password typed into a
# page-level unlock dialog) and only then show the global write-password prompt.
_WRITE_AUTH_HEADERS = {"X-Write-Auth-Required": "1"}
# Only the system password helps here, so the UI must not offer a target password.
_ADMIN_AUTH_HEADERS = {"X-Write-Auth-Required": "admin"}


def _admin_matches(provided: str | None) -> bool:
    return secret_equals(provided, settings.system_password)


def _denied(user: SessionUser | None, role: str) -> HTTPException:
    """No credential fits: a signed-in user lacks the role, anyone else has to sign in."""
    return role_error(role) if user is not None else login_required_error()


async def _require_write(request: Request, x_system_password: str | None, role: str) -> None:
    """A mutating request needs a session of ``role`` or the system password.

    Without OIDC this is the old admin gate: fail-open when no system password
    is set. With OIDC an anonymous caller must sign in (or send the password).
    """
    if request.method not in _MUTATING_METHODS:
        return
    await _require_role(request, x_system_password, role, reading=False)


async def _require_role(request: Request, x_system_password: str | None, role: str, *, reading: bool) -> None:
    """A session of ``role``, else the system password; fail-open without both OIDC and the password."""
    user = await current_user(request)
    if user is not None and user.has_role(role):
        note_credential(request, "session")
        return
    if not settings.system_password:
        if not settings.oidc_enabled:
            return
        raise _denied(user, role)
    key = enforce_auth_throttle(request, SYSTEM_SECRET)
    if _admin_matches(x_system_password):
        record_auth_result(key, True)
        note_credential(request, "system_password")
        return
    # A signed-in user without a password header is not guessing, and neither is
    # a visitor opening a page whose reads need the password.
    if x_system_password or (user is None and not reading):
        record_auth_result(key, False)
    if user is not None:
        raise role_error(role)
    raise HTTPException(
        status_code=401,
        detail="System password required." if reading else "System password required for write operations.",
        headers=with_login_hint(_ADMIN_AUTH_HEADERS),
    )


async def require_admin_read(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> None:
    """The admin gate for every method, reads included.

    For the routers behind the System page: notification channels (their Apprise
    URLs carry tokens), rules and templates, backup exports, sync states and the
    advisory feed list. A signed-in admin or the system password opens them. With
    OIDC an anonymous caller is refused even when ``AUTH_REQUIRE_LOGIN`` is off,
    so a public instance shows its data but not its settings; without OIDC it
    stays fail-open when no system password is set, as every admin gate does.
    """
    await _require_role(
        request, x_system_password, "admin", reading=request.method not in _MUTATING_METHODS,
    )


async def require_admin_write(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> None:
    """Layer A: gate mutating requests behind the admin role or the system password.

    No-op for read methods; fail-open when neither OIDC nor ``SYSTEM_PASSWORD``
    is configured. Safe to attach router-level: read routes pass straight through.
    """
    await _require_write(request, x_system_password, "admin")


async def require_editor_write(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> None:
    """Like the admin gate, but the editor role is enough.

    For writes that are work, not administration: AI analyses without an AI
    password, vulnerability refreshes, inventory, saved searches, new targets.
    Password callers still need the system password, as before.
    """
    await _require_write(request, x_system_password, "editor")


async def require_token_admin(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> None:
    """Gate API token management, reads included.

    Every other list here is public, but this one describes credentials. Unlike
    the admin gate it does not open when no system password is set; a signed-in
    admin passes either way.
    """
    await _require_configured_admin(request, x_system_password, "manage API tokens")


async def _require_configured_admin(request: Request, x_system_password: str | None, action: str) -> None:
    user = await current_user(request)
    if user is not None and user.has_role("admin"):
        note_credential(request, "session")
        return
    if not settings.system_password:
        if user is not None:
            raise role_error("admin")
        if settings.oidc_enabled:
            raise login_required_error(f"Sign in as an admin to {action}.")
        raise HTTPException(status_code=403, detail=f"Set SYSTEM_PASSWORD to {action}.")
    key = enforce_auth_throttle(request, SYSTEM_SECRET)
    if _admin_matches(x_system_password):
        record_auth_result(key, True)
        note_credential(request, "system_password")
        return
    if x_system_password:
        record_auth_result(key, False)
    if user is not None:
        raise role_error("admin")
    raise HTTPException(
        status_code=401,
        detail=f"System password required to {action}.",
        headers=with_login_hint(_ADMIN_AUTH_HEADERS),
    )


async def _authorize_api_token(request: Request, x_api_key: str, scope: str, key: str) -> str | None:
    """Return the name of a valid token holding ``scope``, ``None`` for an unknown one.

    A token without the scope is a real credential, so it gets a 403 and neither
    counts as a guess nor clears the counter for this route.
    """
    if not looks_like_token(x_api_key):
        return None
    token = await (await get_api_token_service()).authenticate(x_api_key)
    if token is None:
        return None
    if scope not in token["scopes"]:
        raise HTTPException(status_code=403, detail=f"API token lacks the {scope} scope.")
    record_auth_result(key, True)
    note_credential(request, "api_token", name=token["name"])
    return token["name"]


async def verify_sca_api_key(
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
) -> None:
    """Authorize a scan submission: ``SCA_API_KEY`` or a ``scan:submit`` token."""
    key = enforce_auth_throttle(request, API_KEY_SECRET)
    if secret_equals(x_api_key, settings.sca_api_key):
        record_auth_result(key, True)
        note_credential(request, "sca_api_key")
        return
    if await _authorize_api_token(request, x_api_key, SCOPE_SCAN_SUBMIT, key) is not None:
        return
    if not settings.sca_api_key:
        service = await get_api_token_service()
        if not await service.has_tokens(SCOPE_SCAN_SUBMIT):
            raise HTTPException(status_code=503, detail="SCA API key not configured on server")
    record_auth_result(key, False)
    raise HTTPException(status_code=401, detail="Invalid API key")


async def require_inventory_report(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> str | None:
    """Authorize a deployment version report and return the token's name, if any.

    Pipelines hold an ``inventory:report`` token, people the system password. The
    SCA API key does not open this route: a version report can make CVE matches
    disappear, which is more than submitting a scan. A wrong token fails outright
    rather than falling through to the password gate, which is fail-open when no
    password is set. A signed-in editor reports like anyone editing the inventory.
    """
    if x_api_key is None:
        await require_editor_write(request, x_system_password=x_system_password)
        return None
    key = enforce_auth_throttle(request, API_KEY_SECRET)
    name = await _authorize_api_token(request, x_api_key, SCOPE_INVENTORY_REPORT, key)
    if name is None:
        record_auth_result(key, False)
        raise HTTPException(status_code=401, detail="Invalid API key")
    return name


async def require_inventory_sync(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
) -> str | None:
    """Authorize a server-list import and return the token's name, if any.

    Scripts hold an ``inventory:sync`` token; people go through the editor gate
    like any inventory change. As with the version report, a wrong token fails
    outright instead of falling through to the (fail-open) password gate: a
    replace import can retire systems.
    """
    if x_api_key is None:
        await require_editor_write(request, x_system_password=x_system_password)
        return None
    key = enforce_auth_throttle(request, API_KEY_SECRET)
    name = await _authorize_api_token(request, x_api_key, SCOPE_INVENTORY_SYNC, key)
    if name is None:
        record_auth_result(key, False)
        raise HTTPException(status_code=401, detail="Invalid API key")
    return name


def _ai_password_matches(provided: str | None) -> bool:
    return secret_equals(provided, settings.ai_analysis_password)


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
    configured, fall back to the editor gate (the role, else the system-password
    modal).

    With OIDC, a signed-in viewer is refused first (viewers only read); an editor
    or admin still needs the AI password when one is set, which keeps it the
    cost lock it is for everyone. A caller without a session keeps the old rule.
    """
    user = await current_user(request)
    if user is not None and not user.has_role("editor"):
        raise role_error("editor")
    if settings.ai_analysis_password:
        key = enforce_auth_throttle(request, AI_SECRET)
        if not _ai_password_matches(x_ai_analysis_password):
            record_auth_result(key, False)
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing AI analysis password.",
            )
        record_auth_result(key, True)
        note_credential(request, "ai_password")
        return
    await require_editor_write(request, x_system_password=x_system_password)


async def require_ai_target_write_scan(
    request: Request,
    scan_id: str,
    x_ai_analysis_password: str | None = Header(default=None, alias=_AI_HEADER),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Authorize a target-scoped AI write (scan AI analysis / attack chain).

    Same precedence as ``require_ai_write``: the AI password alone authorizes
    when configured; otherwise fall back to the per-target write gate (admin
    override or the target's own write password). A signed-in viewer is refused.
    """
    user = await current_user(request)
    if user is not None and not user.has_role("editor"):
        raise role_error("editor")
    if settings.ai_analysis_password:
        key = enforce_auth_throttle(request, AI_SECRET)
        if not _ai_password_matches(x_ai_analysis_password):
            if x_ai_analysis_password:
                record_auth_result(key, False)
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing AI analysis password.",
            )
        record_auth_result(key, True)
        note_credential(request, "ai_password")
        return
    await require_target_write_scan(
        request,
        scan_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def _authorize_target(
    request: Request,
    target_id: str | None,
    *,
    x_system_password: str | None,
    x_target_password: str | None,
    service: ScanService,
    role: str = "editor",
) -> None:
    """Authorize a write scoped to a single target (role, admin override OR target pw).

    ``role`` is what a session needs: editor for ordinary target writes, admin
    for managing the target's password.
    """
    user = await current_user(request)
    if user is not None and user.has_role(role):
        note_credential(request, "session")
        return
    # Checked first: every route below answers 401 or not for a guessed admin
    # password, and the hash comparison below is deliberately slow.
    key = enforce_auth_throttle(request, SYSTEM_SECRET)

    target = await service.target_repo.get(target_id) if target_id else None
    target_hash = target.get("write_password_hash") if target else None

    # A sent target password is checked before the admin password, and when it
    # holds the admin header is never compared. Checked the other way round, its
    # holder could send admin guesses that were never counted (the request still
    # passed) and read the answer from the response time: a right guess skipped
    # the slow hash. A correct target password does not clear the counter either,
    # or its holder could reset it between guesses.
    if (
        x_target_password
        and target_hash
        and await asyncio.to_thread(verify_password, x_target_password, target_hash)
    ):
        note_credential(request, "target_password", target=target_id)
        return

    # Admin override.
    if _admin_matches(x_system_password):
        record_auth_result(key, True)
        note_credential(request, "system_password")
        return

    # Fail-open only when neither the global admin password nor this target's
    # own password is configured, and nobody can sign in.
    if not settings.system_password and not target_hash:
        if not settings.oidc_enabled:
            return
        raise _denied(user, role)

    # No password sent is the UI about to prompt, not a guess: it fans out parallel
    # writes for one merged finding row, which would otherwise lock before the dialog.
    if x_system_password or x_target_password:
        record_auth_result(key, False)
    if user is not None:
        raise role_error(role)
    raise HTTPException(
        status_code=401,
        detail="Write password required for this target.",
        headers=with_login_hint(_WRITE_AUTH_HEADERS),
    )


async def _authorize_targets(
    request: Request,
    target_ids: set[str],
    *,
    x_system_password: str | None,
    x_target_password: str | None,
    service: ScanService,
) -> None:
    """Authorize a write that may span several targets (finding-id batches)."""
    # A non-admin caller can only act when the batch resolves to a single target
    # whose password they hold. Empty set → defer to the no-target path.
    if len(target_ids) <= 1:
        single = next(iter(target_ids), None)
        await _authorize_target(
            request,
            single,
            x_system_password=x_system_password,
            x_target_password=x_target_password,
            service=service,
        )
        return
    user = await current_user(request)
    if user is not None and user.has_role("editor"):
        note_credential(request, "session")
        return
    key = enforce_auth_throttle(request, SYSTEM_SECRET)
    if _admin_matches(x_system_password):
        record_auth_result(key, True)
        note_credential(request, "system_password")
        return
    if x_system_password:
        record_auth_result(key, False)
    if user is not None:
        raise role_error("editor")
    raise HTTPException(
        status_code=401,
        detail="Admin password required: selection spans multiple targets.",
        headers=with_login_hint(_WRITE_AUTH_HEADERS),
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
    request: Request,
    target_id: str = Depends(resolve_target_id_path),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Target id is a path parameter (``/targets/{target_id}``[/check])."""
    await _authorize_target(
        request,
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_write_scan(
    request: Request,
    scan_id: str,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Resolve the owning target from ``scan_id`` in the path."""
    scan = await service.scan_repo.get(scan_id)
    target_id = scan.get("target_id") if scan else None
    await _authorize_target(
        request,
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_password_change(
    request: Request,
    target_id: str = Depends(resolve_target_id_path),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Set, replace or clear a target's write password.

    The admin can, and so can the target's owner with the current password. The
    first password needs the admin, and without SYSTEM_PASSWORD there is none:
    the open admin gate would let anyone clear a password and then write to the
    target, so that case is refused rather than left open. A signed-in admin is
    an admin either way; an editor is an owner only with the current password.
    """
    user = await current_user(request)
    if user is not None and user.has_role("admin"):
        note_credential(request, "session")
        return
    target = await service.target_repo.get(target_id)
    if not settings.system_password and not (target and target.get("write_password_hash")):
        if user is not None:
            raise role_error("admin")
        raise HTTPException(status_code=403, detail="Set SYSTEM_PASSWORD to protect a target with a password.")
    await _authorize_target(
        request,
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
        role="admin",
    )


async def _authorize_sbom_import_token(
    request: Request, x_api_key: str, target_id: str | None, service: ScanService
) -> None:
    """An ``sbom:import`` token: a new target, a check or an existing SBOM-import target.

    Hosts and Kubernetes nodes push their SBOMs from cron or Ansible with it,
    so it must not reach further: a repository or image target is refused, and
    a wrong token fails outright instead of falling through to the password gate.
    """
    key = enforce_auth_throttle(request, API_KEY_SECRET)
    if await _authorize_api_token(request, x_api_key, SCOPE_SBOM_IMPORT, key) is None:
        record_auth_result(key, False)
        raise HTTPException(status_code=401, detail="Invalid API key")
    target = await service.target_repo.get(target_id) if target_id else None
    if target and target.get("type") != "sbom-import":
        raise HTTPException(status_code=403, detail="An sbom:import token only writes SBOM-import targets.")


async def require_target_write_sbom_import(
    request: Request,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """An SBOM import into an existing target takes that target's password; a new target takes the admin's.

    The target is resolved the way the handler resolves it: ImportSbomRequest
    takes the camelCase alias when it is present, even when it is empty, and an
    empty name falls back to the document's own name. Read as ``a or b`` an
    empty ``targetName`` next to ``target_name`` authorized one target while
    the import wrote another.
    """
    body = await _safe_json(request)
    sbom = body.get("sbom")
    fmt = body.get("format")
    _, target_id = resolve_sbom_import_target(
        sbom if isinstance(sbom, dict) else {},
        fmt if isinstance(fmt, str) else None,
        _model_field(body, "targetName", "target_name"),
        _model_field(body, "targetId", "target_id"),
    )
    if body.get("check") is True:
        # A check writes into no target: an editor or the admin, never a target password.
        target_id = None
    if x_api_key is not None:
        await _authorize_sbom_import_token(request, x_api_key, target_id, service)
        return
    await _authorize_target(
        request,
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


def _model_field(body: dict, alias: str, name: str) -> str | None:
    """A string field as a ``populate_by_name`` pydantic model reads it: the alias wins."""
    value = body[alias] if alias in body else body.get(name)
    return value if isinstance(value, str) else None


async def require_target_write_sbom_upload(
    request: Request,
    target_name: str | None = Query(default=None, alias="targetName"),
    format: str | None = Query(default=None),
    check: bool = Query(default=False),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """An SBOM upload into an existing target takes that target's password; a new target takes the admin's.

    Without a usable ``targetName`` the file names the target, so it is read
    here too. "Usable" is the resolver's rule: a blank name (``" "``) counts as
    unset there, and gating it on the default target while the import writes
    into the one the file names opened every protected target.
    Starlette caches the parsed form, and the handler reads the same upload.
    """
    sbom: dict = {}
    if check:
        # A check writes into no target: an editor or the admin, never a target password.
        target_id = None
    else:
        if not (target_name and target_name.strip()):
            sbom = await _uploaded_sbom(request)
        _, target_id = resolve_sbom_import_target(sbom, format, target_name, None)
    if x_api_key is not None:
        await _authorize_sbom_import_token(request, x_api_key, target_id, service)
        return
    await _authorize_target(
        request,
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def _uploaded_sbom(request: Request) -> dict:
    """The uploaded SBOM as the handler will parse it, or ``{}`` (the handler then rejects it)."""
    try:
        upload = (await request.form()).get("file")
    except Exception:
        return {}
    if upload is None or isinstance(upload, str):
        return {}
    limit = settings.sca_source_archive_max_bytes
    content = await upload.read(limit + 1)
    await upload.seek(0)
    if len(content) > limit:
        return {}
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


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
        request,
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_target_write_finding(
    request: Request,
    finding_id: str,
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> None:
    """Resolve the owning target from a single ``finding_id`` path parameter."""
    target_ids = await service.finding_repo.get_target_ids_for_findings([finding_id])
    await _authorize_targets(
        request,
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
        request,
        target_ids,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )


async def require_source_archive_upload(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_system_password: str | None = Header(default=None, alias=_ADMIN_HEADER),
    x_target_password: str | None = Header(default=None, alias=_TARGET_HEADER),
    service: ScanService = Depends(get_scan_service),
) -> bool:
    """Authorize a multipart source-archive upload; True when a pipeline key opened it.

    An uploaded archive always runs as a check, which writes into no target, so
    it takes what a check through ``/scans`` or ``/scans/manual`` takes: the CI
    key or a ``scan:submit`` token, else an editor or the admin. A sent key that
    is wrong fails outright instead of falling through to the password gate.
    """
    if x_api_key is not None:
        await verify_sca_api_key(request, x_api_key)
        return True
    await _authorize_target(
        request,
        None,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )
    return False


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
    # A check (oneTime, or an uploaded archive, which always runs as one) writes
    # into no target, so no target password opens it: an editor or the admin.
    is_check = body.get("check") is True or body.get("oneTime") is True or body.get("one_time") is True or bool(
        body.get("sourceArchiveBase64") or body.get("source_archive_base64")
    )
    if not is_check and isinstance(target, str) and isinstance(target_type, str):
        try:
            target_id = service._derive_target_id(target, target_type)
        except Exception:
            target_id = None
    await _authorize_target(
        request,
        target_id,
        x_system_password=x_system_password,
        x_target_password=x_target_password,
        service=service,
    )
