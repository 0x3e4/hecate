from fastapi import FastAPI

from app.api.v1.routes import api_router
from app.core.config import settings


def create_app() -> FastAPI:
    """Application factory so tests can instantiate the app."""
    app = FastAPI(
        title="Hecate API",
        description="AI-assisted vulnerability intelligence backend.",
        version="0.1.0",
        openapi_url="/api/openapi.json",
    )

    app.include_router(api_router, prefix=settings.api_prefix)
    return app


app = create_app()
