from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes import api_router
from app.core.config import settings
from app.services.scheduling.manager import get_scheduler
from app.services.ingestion.startup_cleanup import cleanup_stale_jobs


def create_app() -> FastAPI:
    """Application factory so tests can instantiate the app."""
    app = FastAPI(
        title="Hecate API",
        description="AI-assisted vulnerability intelligence backend.",
        version="0.1.0",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix=settings.api_prefix)

    @app.on_event("startup")
    async def _startup_scheduler() -> None:  # pragma: no cover - wiring code
        await cleanup_stale_jobs()
        await get_scheduler().start()

    @app.on_event("shutdown")
    async def _shutdown_scheduler() -> None:  # pragma: no cover - wiring code
        await get_scheduler().shutdown()

    return app


app = create_app()
