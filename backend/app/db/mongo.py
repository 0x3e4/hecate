from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import settings

_mongo_client: AsyncIOMotorClient | None = None


async def get_client() -> AsyncIOMotorClient:
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = AsyncIOMotorClient(settings.mongo_url)
    return _mongo_client


async def get_database() -> AsyncIOMotorDatabase:
    client = await get_client()
    return client[settings.mongo_db]
