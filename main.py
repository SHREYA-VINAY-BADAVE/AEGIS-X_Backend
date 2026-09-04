import os
import uvicorn
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from backend.config.settings import settings
from backend.database.connection import get_database, initialize_database
from backend.utils.security import hash_password
from backend.routes.auth import router as auth_router
from backend.routes.scan import router as scan_router
from backend.routes.admin import router as admin_router
from backend.routes.threat import router as events_router, threat_router
from backend.routes.incidents import router as incidents_router
from backend.routes.reports import router as reports_router
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AegisXAPI")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Intelligent Phishing Detection API Using Machine Learning & Explainable AI (SHAP)",
    version="2.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── IP-forwarding middleware ────────────────────────────────────────
@app.middleware("http")
async def inject_client_ip(request: Request, call_next):
    """Store client IP on request.state so route handlers can read it."""
    forwarded = request.headers.get("x-forwarded-for")
    request.state.client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    response = await call_next(request)
    return response

# Attach Routers
app.include_router(auth_router, prefix="/api")
app.include_router(scan_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(threat_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

async def seed_admin():
    """Seed the default administrator user if users collection is empty."""
    db = get_database()
    admin = await db.users.find_one({"role": "admin"})
    if not admin:
        logger.info("No admin user found. Seeding default administrator account...")
        admin_doc = {
            "name": "System Administrator",
            "email": settings.ADMIN_EMAIL,
            "password": hash_password(settings.ADMIN_PASSWORD),
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
            "status": "active"
        }
        await db.users.insert_one(admin_doc)
        logger.info(f"Seeded default admin user: {settings.ADMIN_EMAIL}")

@app.on_event("startup")
async def startup_db_client():
    from backend.database import connection
    initialize_database()
    # Verify database connection asynchronously if not using mock db
    if not connection.use_mock_db and connection.db is not None:
        try:
            # We try to ping the server to ensure we can connect
            await connection.db.client.server_info()
            logger.info("Successfully connected to real MongoDB instance.")
        except Exception as e:
            logger.warning(f"Failed to connect to MongoDB: {e}. Falling back to mongomock.")
            import mongomock
            from backend.database.connection import MockAsyncDatabase
            mock_client = mongomock.MongoClient()
            sync_db = mock_client[settings.DATABASE_NAME]
            connection.db = MockAsyncDatabase(sync_db)
            connection.use_mock_db = True
            logger.info("Mock Database loaded successfully.")
    await seed_admin()
    logger.info("FastAPI application startup sequence completed.")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": "2.0.0",
        "api_docs": "/docs",
        "features": [
            "Real-Time Threat Detection",
            "AI-Based Threat Prediction",
            "Behavioral Analytics",
            "Adaptive Risk Scoring",
            "Automated Incident Response",
            "Malware Detection",
            "Network Intrusion Detection",
            "Security Event Monitoring",
            "Centralized Dashboard",
            "Continuous Learning Engine",
            "Automated Report Generation",
            "Role-Based Access Control",
        ]
    }

if __name__ == "__main__":
    import sys
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
