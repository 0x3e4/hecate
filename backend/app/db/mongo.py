import structlog
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import settings

_mongo_client: AsyncIOMotorClient | None = None
log = structlog.get_logger()


async def get_client() -> AsyncIOMotorClient:
    global _mongo_client
    if _mongo_client is None:
        kwargs: dict = {}

        if settings.mongo_username and settings.mongo_password:
            kwargs["username"] = settings.mongo_username
            kwargs["password"] = settings.mongo_password
            log.info("mongo.auth_enabled")

        if settings.mongo_tls:
            kwargs["tls"] = True
            kwargs["tlsAllowInvalidCertificates"] = True
            log.info("mongo.tls_enabled")

        _mongo_client = AsyncIOMotorClient(settings.mongo_url, **kwargs)

        try:
            info = await _mongo_client.admin.command("ping")
            log.info("mongo.connected", url=settings.mongo_url, ping=info)
        except Exception as exc:
            log.error("mongo.connection_failed", url=settings.mongo_url, error=str(exc))
            _mongo_client = None
            raise

    return _mongo_client


async def get_database() -> AsyncIOMotorDatabase:
    client = await get_client()
    return client[settings.mongo_db]
