from fastapi import APIRouter

from app.core.config import settings

router = APIRouter()


@router.get("/health")
async def get_health() -> dict[str, str]:
    """Simple liveness probe."""
    return {
        "status": "ok",
        "environment": settings.environment,
        "service": "hecate-backend",
    }
