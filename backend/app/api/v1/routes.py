from fastapi import APIRouter

from app.api.v1 import (
    assets,
    audit,
    backup,
    changelog,
    cpe,
    cwe,
    saved_searches,
    stats,
    status,
    sync,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(status.router, prefix="/status", tags=["status"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(saved_searches.router, prefix="/saved-searches", tags=["saved-searches"])
api_router.include_router(cpe.router, prefix="/cpe", tags=["cpe"])
api_router.include_router(cwe.router, prefix="/cwe", tags=["cwe"])
api_router.include_router(assets.router, prefix="/assets", tags=["assets"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(stats.router, prefix="/stats", tags=["stats"])
api_router.include_router(changelog.router, prefix="/changelog", tags=["changelog"])
api_router.include_router(backup.router, prefix="/backup", tags=["backup"])
api_router.include_router(sync.router, prefix="/sync", tags=["sync"])
