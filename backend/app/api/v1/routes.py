from fastapi import APIRouter, Depends

from app.core.auth_context import require_read_access
from app.core.write_auth import require_admin_read, require_admin_write, require_editor_write, require_token_admin
from app.api.v1 import (
    advisory_feeds,
    api_tokens,
    app_settings,
    assets,
    audit,
    auth,
    backup,
    capec,
    changelog,
    config,
    cpe,
    cwe,
    events,
    inventory,
    inventory_systems,
    license_policies,
    malware,
    notifications,
    packages,
    saved_searches,
    scans,
    stats,
    status,
    sync,
    version,
    vex_rules,
    vulnerabilities,
)

# With AUTH_REQUIRE_LOGIN every route below needs a session or another credential;
# the gate itself lets PUBLIC_ROUTES (health, config, shields, /auth/*) through.
api_router = APIRouter(dependencies=[Depends(require_read_access)])

# Write-protection (Layer A): routers below whose every mutating endpoint is a
# genuine admin write (no POST-as-read endpoints) get the global admin gate at
# include time, so all current and future writes in them are covered. The
# ``scans`` and ``vulnerabilities`` routers are gated per-route instead because
# they mix reads, POST-reads (``/vulnerabilities/search``), CI key auth
# (``POST /scans``) and per-target delegation. ``status`` is NOT gated — its
# ``POST /status/system-auth`` must stay reachable to verify the password.
_admin_write = [Depends(require_admin_write)]
# Writes that are work rather than administration: an OIDC editor passes, password
# callers still need the system password (the same secret as before).
_editor_write = [Depends(require_editor_write)]
# Settings behind the System page: their reads need the admin too (notification
# channel URLs carry tokens, backups are whole datasets). With OIDC this holds
# even when AUTH_REQUIRE_LOGIN is off, so a public instance shows its data, not
# its configuration or its audit log. license_policies and vex_rules stay readable: the scan
# pages show them.
_admin_all = [Depends(require_admin_read)]

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(status.router, prefix="/status", tags=["status"])
api_router.include_router(config.router, tags=["config"])
api_router.include_router(app_settings.router, tags=["app-settings"], dependencies=_admin_write)
api_router.include_router(
    api_tokens.router, prefix="/api-tokens", tags=["api-tokens"], dependencies=[Depends(require_token_admin)]
)
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(
    saved_searches.router, prefix="/saved-searches", tags=["saved-searches"], dependencies=_editor_write
)
api_router.include_router(cpe.router, prefix="/cpe", tags=["cpe"])
# Read-only (GET): the pre-install package check for agents and CI.
api_router.include_router(packages.router, prefix="/packages", tags=["packages"])
api_router.include_router(cwe.router, prefix="/cwe", tags=["cwe"])
api_router.include_router(capec.router, prefix="/capec", tags=["capec"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"], dependencies=_admin_all)
api_router.include_router(stats.router, prefix="/stats", tags=["stats"])
api_router.include_router(changelog.router, prefix="/changelog", tags=["changelog"])
api_router.include_router(backup.router, prefix="/backup", tags=["backup"], dependencies=_admin_all)
api_router.include_router(sync.router, prefix="/sync", tags=["sync"], dependencies=_admin_all)
api_router.include_router(
    advisory_feeds.router, prefix="/advisory-feeds", tags=["advisory-feeds"], dependencies=_admin_all
)
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(
    notifications.router, prefix="/notifications", tags=["notifications"], dependencies=_admin_all
)
api_router.include_router(
    license_policies.router, prefix="/license-policies", tags=["license-policies"], dependencies=_admin_write
)
api_router.include_router(vex_rules.router, prefix="/vex-rules", tags=["vex-rules"], dependencies=_admin_write)
api_router.include_router(inventory.report_router, prefix="/inventory", tags=["inventory"])
# Before the inventory router: its /{item_id} would take "systems" for an item id.
api_router.include_router(
    inventory_systems.router, prefix="/inventory/systems", tags=["inventory"], dependencies=_editor_write
)
api_router.include_router(inventory.router, prefix="/inventory", tags=["inventory"], dependencies=_editor_write)
api_router.include_router(events.router, prefix="/events", tags=["events"])
api_router.include_router(malware.router, prefix="/malware", tags=["malware"])
api_router.include_router(version.router, tags=["version"])
