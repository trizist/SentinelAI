from fastapi import FastAPI, Depends, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from app.core.config import settings
# Gradually add routers one by one to isolate any issues
from app.api.endpoints import auth, incidents, analysis, threats
from app.db.base import Base, engine
import logging
from datetime import datetime
import asyncio
import redis.asyncio as redis
import os

# Configure logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(settings.LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Set up CORS middleware with detailed configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
    expose_headers=["Content-Range", "Range", "Authorization"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Create API router with all endpoints
api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Mount static files for the dashboard
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app", "static")
if os.path.exists(static_dir):
    app.mount("/dashboard", StaticFiles(directory=static_dir, html=True), name="dashboard")
    logger.info(f"Mounted dashboard static files from {static_dir}")
else:
    logger.warning(f"Static directory not found at {static_dir}")

@app.get("/")
async def root():
    return {
        "message": "Welcome to CyberCare AI-Powered Cyber Responder",
        "version": settings.VERSION,
        "documentation": "/docs"
    }

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.VERSION
    }

@app.get("/health", status_code=200)
async def docker_health_check():
    """
    Health check endpoint for Docker healthchecks
    """
    return {"status": "ok", "message": "Service is healthy"}

@app.get("/test")
async def test_endpoint():
    """Simple test endpoint that doesn't require any complex dependencies"""
    try:
        from app.models.ai.threat_classifier import AI_DEPENDENCIES_AVAILABLE
        ai_status = "AVAILABLE" if AI_DEPENDENCIES_AVAILABLE else "NOT AVAILABLE"
    except Exception as e:
        ai_status = f"ERROR: {str(e)}"
        
    return {
        "status": "ok", 
        "message": "Test endpoint", 
        "ai_dependencies": ai_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.on_event("startup")
async def startup_event():
    """Initialize application services on startup."""
    try:
        # Create database tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}")
        # Just log the error but don't raise it to prevent app from failing to start
        logger.exception("Detailed error during startup:")

    try:
        # Try connecting to Redis
        redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
        await redis_client.ping()
        logger.info("Successfully connected to Redis")
    except Exception as e:
        logger.warning(f"Redis connection failed: {str(e)}")
        logger.exception("Detailed Redis connection error:")
    
    try:
        # Log AI dependencies status
        from app.models.ai.threat_classifier import AI_DEPENDENCIES_AVAILABLE
        if AI_DEPENDENCIES_AVAILABLE:
            logger.info("AI dependencies are available and ready")
        else:
            logger.warning("AI dependencies are NOT available - running in limited mode")
    except Exception as e:
        logger.warning(f"Failed to check AI dependencies status: {str(e)}")
        logger.exception("AI dependency check error:")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown."""
    try:
        await engine.dispose()
        logger.info("Database connection closed")
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}")
        # Don't raise as we're shutting down anyway
