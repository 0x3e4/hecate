from fastapi import APIRouter, Depends

from app.core.write_auth import require_admin_write
from app.api.v1 import (
    assets,
    audit,
    backup,
    capec,
    changelog,
    config,
    cpe,
    cwe,
    events,
    inventory,
    license_policies,
    malware,
    notifications,
    saved_searches,
    scans,
    stats,
    status,
    sync,
    version,
    vulnerabilities,
)

api_router = APIRouter()

# Write-protection (Layer A): routers below whose every mutating endpoint is a
# genuine admin write (no POST-as-read endpoints) get the global admin gate at
# include time, so all current and future writes in them are covered. The
# ``scans`` and ``vulnerabilities`` routers are gated per-route instead because
# they mix reads, POST-reads (``/vulnerabilities/search``), CI key auth
# (``POST /scans``) and per-target delegation. ``status`` is NOT gated — its
# ``POST /status/system-auth`` must stay reachable to verify the password.
_admin_write = [Depends(require_admin_write)]

api_router.include_router(status.router, prefix="/status", tags=["status"])
api_router.include_router(config.router, tags=["config"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(
    saved_searches.router, prefix="/saved-searches", tags=["saved-searches"], dependencies=_admin_write
)
api_router.include_router(cpe.router, prefix="/cpe", tags=["cpe"])
api_router.include_router(cwe.router, prefix="/cwe", tags=["cwe"])
api_router.include_router(capec.router, prefix="/capec", tags=["capec"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(stats.router, prefix="/stats", tags=["stats"])
api_router.include_router(changelog.router, prefix="/changelog", tags=["changelog"])
api_router.include_router(backup.router, prefix="/backup", tags=["backup"], dependencies=_admin_write)
api_router.include_router(sync.router, prefix="/sync", tags=["sync"], dependencies=_admin_write)
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(
    notifications.router, prefix="/notifications", tags=["notifications"], dependencies=_admin_write
)
api_router.include_router(
    license_policies.router, prefix="/license-policies", tags=["license-policies"], dependencies=_admin_write
)
api_router.include_router(inventory.router, prefix="/inventory", tags=["inventory"], dependencies=_admin_write)
api_router.include_router(events.router, prefix="/events", tags=["events"])
api_router.include_router(malware.router, prefix="/malware", tags=["malware"])
api_router.include_router(version.router, tags=["version"])
