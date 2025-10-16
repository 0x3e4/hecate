from fastapi import APIRouter

from app.api.v1 import status
from app.api.v1 import vulnerabilities

api_router = APIRouter()
api_router.include_router(status.router, prefix="/status", tags=["status"])
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
