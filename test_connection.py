import asyncio
import logging
from backend.config.settings import settings
from backend.database.connection import get_database
from backend.database import connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestConnection")

async def run_test():
    logger.info("Starting connection test...")
    logger.info("Loaded MongoDB configuration for database %s.", settings.DATABASE_NAME)

    # Initialize connection
    await connection.verify_database_connection()
    db = get_database()

    try:
        # 1. Check server connectivity
        await db.command("ping")
        logger.info("Successfully pinged configured MongoDB deployment.")

        # 2. Test Write operation
        from uuid import uuid4
        test_name = f"test_connection_{uuid4().hex}"
        test_doc = {"name": test_name, "data": 12345}
        insert_result = await db.test_connection_temp.insert_one(test_doc)
        logger.info("Insert test successful. Inserted ID: %s", insert_result.inserted_id)

        # 3. Test Read operation
        found_doc = await db.test_connection_temp.find_one({"_id": insert_result.inserted_id})
        if found_doc:
            logger.info("Read test successful.")
        else:
            logger.error("Read test failed: Document not found.")
            return False

        # 4. Test Delete operation
        delete_result = await db.test_connection_temp.delete_one({"_id": insert_result.inserted_id})
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
