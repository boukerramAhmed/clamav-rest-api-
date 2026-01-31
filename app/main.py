import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import scan
from app.services.clamav_client import clamav_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup and shutdown event handler.

    Connects to ClamAV on startup and logs the connection status.
    """
    # Startup
    logger.info("Starting ClamAV API...")
    connected = clamav_client.connect()
    if connected:
        logger.info("ClamAV client connected successfully")
    else:
        logger.warning("Failed to connect to ClamAV, will retry on first request")

    yield

    # Shutdown
    logger.info("Shutting down ClamAV API...")
    clamav_client.disconnect()
    logger.info("ClamAV client disconnected")


# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="REST API for scanning files using ClamAV",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router)


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": "REST API for scanning files using ClamAV",
        "endpoints": {
            "scan": "POST /api/v1/scan",
            "health": "GET /api/v1/health",
            "version": "GET /api/v1/version",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
