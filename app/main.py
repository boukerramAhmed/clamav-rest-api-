import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import scan
from app.services.cache import cache_client
from app.services.clamav_client import clamav_client
from app.services.kafka_producer import kafka_producer
from app.services.rabbitmq_producer import rabbitmq_producer
from app.services.s3_client import s3_client

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

    Connects to ClamAV, Redis, S3, and Kafka on startup.
    """
    # Startup
    logger.info("Starting ClamAV API...")

    # Connect to ClamAV
    clamav_connected = clamav_client.connect()
    if clamav_connected:
        logger.info("ClamAV client connected successfully")
    else:
        logger.warning("Failed to connect to ClamAV, will retry on first request")

    # Connect to Redis cache
    cache_connected = cache_client.connect()
    if cache_connected:
        logger.info("Redis cache connected successfully")
    else:
        logger.warning("Failed to connect to Redis, caching disabled")

    # Connect to S3 (MinIO)
    if settings.enable_s3:
        s3_connected = s3_client.connect()
        if s3_connected:
            logger.info("S3 client connected successfully")
        else:
            logger.warning("Failed to connect to S3, S3 scanning disabled")
    else:
        logger.info("S3 scanning is disabled")

    # Connect to Kafka (Redpanda)
    if settings.enable_kafka:
        kafka_connected = await kafka_producer.connect()
        if kafka_connected:
            logger.info("Kafka producer connected successfully")
        else:
            logger.warning("Failed to connect to Kafka, Kafka scanning disabled")
    else:
        logger.info("Kafka integration is disabled")

    # Connect to RabbitMQ
    if settings.enable_rabbitmq:
        rabbitmq_connected = rabbitmq_producer.connect()
        if rabbitmq_connected:
            logger.info("RabbitMQ producer connected successfully")
        else:
            logger.warning("Failed to connect to RabbitMQ, RabbitMQ scanning disabled")
    else:
        logger.info("RabbitMQ integration is disabled")

    yield

    # Shutdown
    logger.info("Shutting down ClamAV API...")
    clamav_client.disconnect()
    cache_client.disconnect()
    if settings.enable_s3:
        s3_client.disconnect()
    if settings.enable_kafka:
        await kafka_producer.disconnect()
    if settings.enable_rabbitmq:
        rabbitmq_producer.disconnect()
    logger.info("All clients disconnected")


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

# Include routershttp://localhost:15672
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
            "scan-s3": "POST /api/v1/scan-s3",
            "scan-s3-rabbitmq": "POST /api/v1/scan-s3-rabbitmq",
            "health": "GET /api/v1/health",
            "version": "GET /api/v1/version",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
