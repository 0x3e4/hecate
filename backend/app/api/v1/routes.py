from fastapi import APIRouter

from app.api.v1 import audit, cpe, status, vulnerabilities

api_router = APIRouter()
api_router.include_router(status.router, prefix="/status", tags=["status"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(cpe.router, prefix="/cpe", tags=["cpe"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
