import logging

from motor.motor_asyncio import AsyncIOMotorClient

from backend.config.settings import settings

logger = logging.getLogger("Database")

client: AsyncIOMotorClient | None = None
db = None


def initialize_database():
    """Create one MongoDB client for the application process.

    Motor connects lazily, so callers must use ``verify_database_connection``
    before accepting requests that depend on persistence.
    """
    global client, db
    if client is None:
        client = AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            appname="AEGIS-X",
        )
        db = client[settings.DATABASE_NAME]
        logger.info("MongoDB client initialized for database %s.", settings.DATABASE_NAME)
    return db


async def verify_database_connection() -> None:
    """Ping MongoDB and fail startup if persistence is unavailable."""
    database = initialize_database()
    try:
        await database.command("ping")
    except Exception:
        logger.exception("MongoDB ping failed for database %s.", settings.DATABASE_NAME)
        raise RuntimeError("MongoDB is unavailable; refusing to start without persistent storage.") from None
    logger.info("MongoDB ping succeeded for database %s.", settings.DATABASE_NAME)


def get_database():
    if db is None:
        return initialize_database()
    return db


async def close_database() -> None:
    global client, db
    if client is not None:
        client.close()
        client = None
        db = None
