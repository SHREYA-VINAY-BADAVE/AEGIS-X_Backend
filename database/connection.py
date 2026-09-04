import logging
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import mongomock
from backend.config.settings import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Database")

# Pure Python wrapper to make mongomock collections asynchronous
class MockAsyncCursor:
    def __init__(self, sync_cursor):
        self.sync_cursor = sync_cursor
        self.iter_items = None
        
    async def to_list(self, length=None):
        lst = list(self.sync_cursor)
        if length is not None:
            return lst[:length]
        return lst
        
    def __aiter__(self):
        self.iter_items = iter(self.sync_cursor)
        return self
        
    async def __anext__(self):
        await asyncio.sleep(0)  # yield control
        try:
            return next(self.iter_items)
        except StopIteration:
            raise StopAsyncIteration

class MockAsyncCollection:
    def __init__(self, sync_collection):
        self._sync_collection = sync_collection
        
    async def insert_one(self, document):
        await asyncio.sleep(0)
        res = self._sync_collection.insert_one(document)
        return res
        
    async def find_one(self, filter_query, *args, **kwargs):
        await asyncio.sleep(0)
        res = self._sync_collection.find_one(filter_query, *args, **kwargs)
        return res
        
    def find(self, filter_query=None, *args, **kwargs):
        cursor = self._sync_collection.find(filter_query or {}, *args, **kwargs)
        return MockAsyncCursor(cursor)
        
    async def update_one(self, filter_query, update_query, upsert=False, *args, **kwargs):
        await asyncio.sleep(0)
        res = self._sync_collection.update_one(filter_query, update_query, upsert=upsert, *args, **kwargs)
        return res
        
    async def delete_one(self, filter_query, *args, **kwargs):
        await asyncio.sleep(0)
        res = self._sync_collection.delete_one(filter_query, *args, **kwargs)
        return res
        
    async def count_documents(self, filter_query, *args, **kwargs):
        await asyncio.sleep(0)
        res = self._sync_collection.count_documents(filter_query, *args, **kwargs)
        return res

class MockAsyncDatabase:
    def __init__(self, sync_db):
        self._sync_db = sync_db
        self.collections = {}
        
    def __getattr__(self, name):
        if name not in self.collections:
            self.collections[name] = MockAsyncCollection(self._sync_db[name])
        return self.collections[name]
        
    def __getitem__(self, name):
        return self.__getattr__(name)

db = None
use_mock_db = False

def initialize_database():
    global db, use_mock_db
    try:
        logger.info(f"Connecting to MongoDB at: {settings.MONGODB_URI}")
        # Build standard Async client
        client = AsyncIOMotorClient(settings.MONGODB_URI, serverSelectionTimeoutMS=2000)
        db = client[settings.DATABASE_NAME]
        logger.info("MongoDB client wrapper initialized.")
    except Exception as e:
        logger.warning(f"Failed to initialize MongoDB client: {e}. Falling back to mongomock.")
        # Fallback to mongomock
        mock_client = mongomock.MongoClient()
        sync_db = mock_client[settings.DATABASE_NAME]
        db = MockAsyncDatabase(sync_db)
        use_mock_db = True
        logger.info("Mock Database loaded successfully.")
    return db

def get_database():
    global db
    if db is None:
        db = initialize_database()
    return db
