import asyncio
import logging
from backend.config.settings import settings
from backend.database.connection import get_database, initialize_database
from backend.database import connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestConnection")

async def run_test():
    logger.info("Starting connection test...")
    logger.info(f"Loaded database URI: {settings.MONGODB_URI}")
    logger.info(f"Loaded database name: {settings.DATABASE_NAME}")

    # Initialize connection
    initialize_database()
    db = get_database()

    if connection.use_mock_db:
        logger.error("Database connection fell back to MOCK DATABASE. Real MongoDB Atlas connection failed.")
        return False

    try:
        # 1. Check server info
        server_info = await db.client.server_info()
        logger.info(f"Successfully pinged MongoDB Atlas. Server Info: {server_info.get('version', 'unknown version')}")

        # 2. Test Write operation
        test_doc = {"name": "test_connection", "data": 12345}
        insert_result = await db.test_connection_temp.insert_one(test_doc)
        logger.info(f"Insert test successful. Inserted ID: {insert_result.inserted_id}")

        # 3. Test Read operation
        found_doc = await db.test_connection_temp.find_one({"name": "test_connection"})
        if found_doc:
            logger.info("Read test successful.")
        else:
            logger.error("Read test failed: Document not found.")
            return False

        # 4. Test Delete operation
        delete_result = await db.test_connection_temp.delete_one({"name": "test_connection"})
        if delete_result.deleted_count > 0:
            logger.info("Delete test successful. Temporary test document deleted.")
        else:
            logger.error("Delete test failed.")
            return False

        logger.info("All connection tests PASSED successfully!")
        return True
    
    except Exception as e:
        logger.error(f"Error occurred during MongoDB Atlas connection test: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_test())
    if not success:
        exit(1)
