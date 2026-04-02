from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes import api_router
from app.core.config import settings
from app.core.logging_config import configure_logging
from app.services.scheduling.manager import get_scheduler
from app.services.ingestion.startup_cleanup import cleanup_stale_jobs
from app.services.stats_service import get_stats_service
from app.services.cwe_service import get_cwe_service

# Configure logging at module import time
configure_logging()


def create_app() -> FastAPI:
    """Application factory so tests can instantiate the app."""
    app = FastAPI(
        title="Hecate API",
        description="AI-assisted vulnerability intelligence backend.",
        version="0.1.0",
        openapi_url="/api/openapi.json",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
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
        # Warm up caches in background to improve first page load
        import asyncio
        asyncio.create_task(_warm_stats_cache())
        asyncio.create_task(_warm_cwe_cache())

    async def _warm_stats_cache() -> None:  # pragma: no cover - cache warming
        """Warm up the stats cache on startup to improve first request performance."""
        try:
            import structlog
            log = structlog.get_logger()
            log.info("stats.cache_warming_started")
            stats_service = get_stats_service()
            await stats_service.get_overview()
            log.info("stats.cache_warming_completed")
        except Exception as e:
            import structlog
            log = structlog.get_logger()
            log.warning("stats.cache_warming_failed", error=str(e))

    async def _warm_cwe_cache() -> None:  # pragma: no cover - cache warming
        """Prefetch common CWE descriptions for AI analysis."""
        try:
            import structlog
            log = structlog.get_logger()
            log.info("cwe.cache_warming_started")
            cwe_service = get_cwe_service()
            prefetched = await cwe_service.prefetch_common_cwes()
            log.info("cwe.cache_warming_completed", prefetched=prefetched)
        except Exception as e:
            import structlog
            log = structlog.get_logger()
            log.warning("cwe.cache_warming_failed", error=str(e))

    @app.on_event("shutdown")
    async def _shutdown_scheduler() -> None:  # pragma: no cover - wiring code
        await get_scheduler().shutdown()

    return app


app = create_app()
