import asyncio
import hashlib
import io
import logging
import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile, status

from app.config import settings
from app.models import (
    FileScanResult,
    HealthResponse,
    S3RabbitMQScanRequest,
    S3ScanAccepted,
    S3ScanRequest,
    ScanResponse,
    VersionResponse,
)
from app.services.cache import cache_client
from app.services.clamav_client import clamav_client
from app.services.kafka_producer import TopicNotFoundError, kafka_producer
from app.services.rabbitmq_producer import rabbitmq_producer
from app.services.s3_client import s3_client

router = APIRouter(prefix="/api/v1", tags=["scan"])
logger = logging.getLogger(__name__)


@router.post("/scan", response_model=ScanResponse)
async def scan_files(files: List[UploadFile] = File(...)):
    """
    Scan multiple files for viruses.

    - **files**: List of files to scan (multipart/form-data)

    Returns detailed scan results for each file.
    """
    if not clamav_client.client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ClamAV service is not available",
        )

    if len(files) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one file must be provided",
        )

    if len(files) > settings.max_files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Maximum {settings.max_files} files allowed per request",
        )

    results = []
    clean_count = 0
    infected_count = 0
    error_count = 0

    for file in files:
        # Read file content
        file_content = await file.read()
        filename = file.filename or "unknown"

        # Validate file size
        if len(file_content) > settings.max_file_size:
            results.append(FileScanResult(
                filename=filename,
                size_bytes=len(file_content),
                sha256_hash="",
                status="error",
                virus_signature=None,
                scan_time_seconds=0,
                timestamp=datetime.utcnow(),
                cached=False,
            ))
            error_count += 1
            logger.warning(
                f"File {filename} exceeds max size of {settings.max_file_size} bytes"
            )
            continue

        # Calculate SHA256 hash
        sha256_hash = hashlib.sha256(file_content).hexdigest()

        # Check cache for existing result
        cached_result = cache_client.get_scan_result(sha256_hash)
        if cached_result:
            # Return cached result with updated filename and timestamp
            cached_result.filename = filename
            cached_result.timestamp = datetime.utcnow()
            cached_result.cached = True

            if cached_result.status == "clean":
                clean_count += 1
            elif cached_result.status == "infected":
                infected_count += 1
            else:
                error_count += 1

            results.append(cached_result)
            logger.info(f"Cache hit for {filename} (hash: {sha256_hash[:16]}...)")
            continue

        # Reset file pointer for scanning
        await file.seek(0)

        # Scan the file
        try:
            result, error = clamav_client.scan_stream(file.file, filename)

            if error:
                error_count += 1
                logger.error(f"Scan error for {filename}: {error}")
            elif result.status == "clean":
                clean_count += 1
            elif result.status == "infected":
                infected_count += 1

            # Cache the result
            cache_client.set_scan_result(sha256_hash, result)

            results.append(result)

        except Exception as e:
            error_count += 1
            logger.error(f"Unexpected error scanning {filename}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while scanning files",
            )

    return ScanResponse(
        total_files=len(files),
        clean_files=clean_count,
        infected_files=infected_count,
        error_files=error_count,
        results=results,
    )


async def process_s3_scan(request_id: str, s3_key: str, s3_bucket: str, kafka_topic: str):
    """
    Background task to process S3 file scan.

    1. Download file from S3
    2. Calculate SHA256, check cache
    3. If not cached, scan with ClamAV
    4. Cache result
    5. Send result to Kafka
    """
    logger.info(f"[{request_id}] Starting S3 scan for {s3_key}")

    try:
        # Download file from S3
        file_content = s3_client.download_file(s3_key, s3_bucket)
        if file_content is None:
            error_result = {
                "request_id": request_id,
                "s3_key": s3_key,
                "s3_bucket": s3_bucket,
                "status": "error",
                "error": "Failed to download file from S3",
                "timestamp": datetime.utcnow().isoformat(),
            }
            await kafka_producer.send_result(kafka_topic, error_result)
            logger.error(f"[{request_id}] Failed to download {s3_key} from S3")
            return

        # Calculate SHA256 hash
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        logger.info(f"[{request_id}] File hash: {sha256_hash[:16]}...")

        # Check cache
        cached_result = cache_client.get_scan_result(sha256_hash)
        if cached_result:
            cached_result.filename = s3_key
            cached_result.timestamp = datetime.utcnow()
            cached_result.cached = True

            result_dict = cached_result.model_dump()
            result_dict["request_id"] = request_id
            result_dict["s3_key"] = s3_key
            result_dict["s3_bucket"] = s3_bucket
            result_dict["timestamp"] = result_dict["timestamp"].isoformat()

            await kafka_producer.send_result(kafka_topic, result_dict)
            logger.info(f"[{request_id}] Cache hit, sent result to Kafka")
            return

        # Scan with ClamAV
        if not clamav_client.client:
            error_result = {
                "request_id": request_id,
                "s3_key": s3_key,
                "s3_bucket": s3_bucket,
                "status": "error",
                "error": "ClamAV service not available",
                "timestamp": datetime.utcnow().isoformat(),
            }
            await kafka_producer.send_result(kafka_topic, error_result)
            logger.error(f"[{request_id}] ClamAV not available")
            return

        file_stream = io.BytesIO(file_content)
        result, error = clamav_client.scan_stream(file_stream, s3_key)

        if error:
            logger.error(f"[{request_id}] Scan error: {error}")

        # Cache the result
        cache_client.set_scan_result(sha256_hash, result)

        # Send result to Kafka
        result_dict = result.model_dump()
        result_dict["request_id"] = request_id
        result_dict["s3_key"] = s3_key
        result_dict["s3_bucket"] = s3_bucket
        result_dict["timestamp"] = result_dict["timestamp"].isoformat()

        await kafka_producer.send_result(kafka_topic, result_dict)
        logger.info(f"[{request_id}] Scan complete, sent result to Kafka (status: {result.status})")

    except Exception as e:
        logger.error(f"[{request_id}] Unexpected error: {e}")
        error_result = {
            "request_id": request_id,
            "s3_key": s3_key,
            "s3_bucket": s3_bucket,
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            await kafka_producer.send_result(kafka_topic, error_result)
        except Exception as kafka_error:
            logger.error(f"[{request_id}] Failed to send error to Kafka: {kafka_error}")


async def process_s3_scan_rabbitmq(request_id: str, s3_key: str, s3_bucket: str, rabbitmq_queue: str):
    """
    Background task to process S3 file scan and publish result to RabbitMQ.

    1. Download file from S3
    2. Calculate SHA256, check cache
    3. If not cached, scan with ClamAV
    4. Cache result
    5. Send result to RabbitMQ
    """
    logger.info(f"[{request_id}] Starting S3 scan for {s3_key} (RabbitMQ)")

    try:
        # Download file from S3
        file_content = s3_client.download_file(s3_key, s3_bucket)
        if file_content is None:
            error_result = {
                "request_id": request_id,
                "s3_key": s3_key,
                "s3_bucket": s3_bucket,
                "status": "error",
                "error": "Failed to download file from S3",
                "timestamp": datetime.utcnow().isoformat(),
            }
            await rabbitmq_producer.send_result(error_result, rabbitmq_queue)
            logger.error(f"[{request_id}] Failed to download {s3_key} from S3")
            return

        # Calculate SHA256 hash
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        logger.info(f"[{request_id}] File hash: {sha256_hash[:16]}...")

        # Check cache
        cached_result = cache_client.get_scan_result(sha256_hash)
        if cached_result:
            cached_result.filename = s3_key
            cached_result.timestamp = datetime.utcnow()
            cached_result.cached = True

            result_dict = cached_result.model_dump()
            result_dict["request_id"] = request_id
            result_dict["s3_key"] = s3_key
            result_dict["s3_bucket"] = s3_bucket
            result_dict["timestamp"] = result_dict["timestamp"].isoformat()

            await rabbitmq_producer.send_result(result_dict, rabbitmq_queue)
            logger.info(f"[{request_id}] Cache hit, sent result to RabbitMQ")
            return

        # Scan with ClamAV
        if not clamav_client.client:
            error_result = {
                "request_id": request_id,
                "s3_key": s3_key,
                "s3_bucket": s3_bucket,
                "status": "error",
                "error": "ClamAV service not available",
                "timestamp": datetime.utcnow().isoformat(),
            }
            await rabbitmq_producer.send_result(error_result, rabbitmq_queue)
            logger.error(f"[{request_id}] ClamAV not available")
            return

        file_stream = io.BytesIO(file_content)
        result, error = clamav_client.scan_stream(file_stream, s3_key)

        if error:
            logger.error(f"[{request_id}] Scan error: {error}")

        # Cache the result
        cache_client.set_scan_result(sha256_hash, result)

        # Send result to RabbitMQ
        result_dict = result.model_dump()
        result_dict["request_id"] = request_id
        result_dict["s3_key"] = s3_key
        result_dict["s3_bucket"] = s3_bucket
        result_dict["timestamp"] = result_dict["timestamp"].isoformat()

        await rabbitmq_producer.send_result(result_dict, rabbitmq_queue)
        logger.info(f"[{request_id}] Scan complete, sent result to RabbitMQ (status: {result.status})")

    except Exception as e:
        logger.error(f"[{request_id}] Unexpected error: {e}")
        error_result = {
            "request_id": request_id,
            "s3_key": s3_key,
            "s3_bucket": s3_bucket,
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            await rabbitmq_producer.send_result(error_result, rabbitmq_queue)
        except Exception as rabbitmq_error:
            logger.error(f"[{request_id}] Failed to send error to RabbitMQ: {rabbitmq_error}")


@router.post("/scan/kafka", response_model=S3ScanAccepted, status_code=202)
async def scan_s3_file(request: S3ScanRequest, background_tasks: BackgroundTasks):
    """
    Scan a file from S3 asynchronously.

    - **s3_key**: S3 object key of the file to scan
    - **kafka_topic**: Kafka topic to send the scan result to
    - **s3_bucket**: Optional bucket name (uses default if not specified)

    Returns 202 Accepted immediately. The scan result will be sent to the specified Kafka topic.
    """
    # Validate services are enabled
    if not settings.enable_s3:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="S3 scanning is not enabled",
        )

    if not settings.enable_kafka:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Kafka integration is not enabled",
        )

    # Validate services are available
    if not s3_client.client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="S3 service is not available",
        )

    if not kafka_producer.producer:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Kafka service is not available",
        )

    # Generate request ID and resolve defaults
    request_id = str(uuid.uuid4())
    s3_bucket = request.s3_bucket or settings.s3_bucket
    kafka_topic = request.kafka_topic or settings.kafka_topic

    # Validate S3 file exists
    if not s3_client.file_exists(request.s3_key, s3_bucket):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{request.s3_key}' not found in bucket '{s3_bucket}'",
        )

    # Validate Kafka topic exists
    if not await kafka_producer.topic_exists(kafka_topic):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Kafka topic '{kafka_topic}' does not exist",
        )

    # Add background task
    background_tasks.add_task(
        process_s3_scan,
        request_id,
        request.s3_key,
        s3_bucket,
        kafka_topic,
    )

    logger.info(f"[{request_id}] Accepted scan request for s3://{s3_bucket}/{request.s3_key}")

    return S3ScanAccepted(
        request_id=request_id,
        status="accepted",
        message=f"Scan request accepted. Result will be sent to Kafka topic '{request.kafka_topic}'",
    )


@router.post("/scan/rabbitmq", response_model=S3ScanAccepted, status_code=202)
async def scan_s3_file_rabbitmq(request: S3RabbitMQScanRequest, background_tasks: BackgroundTasks):
    """
    Scan a file from S3 asynchronously and publish result to RabbitMQ.

    - **s3_key**: S3 object key of the file to scan
    - **rabbitmq_queue**: RabbitMQ queue to send the scan result to
    - **s3_bucket**: Optional bucket name (uses default if not specified)

    Returns 202 Accepted immediately. The scan result will be sent to the specified RabbitMQ queue.
    """
    # Validate services are enabled
    if not settings.enable_s3:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="S3 scanning is not enabled",
        )

    if not settings.enable_rabbitmq:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="RabbitMQ integration is not enabled",
        )

    # Validate services are available
    if not s3_client.client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="S3 service is not available",
        )

    if not rabbitmq_producer.channel:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RabbitMQ service is not available",
        )

    # Generate request ID and resolve defaults
    request_id = str(uuid.uuid4())
    s3_bucket = request.s3_bucket or settings.s3_bucket
    rabbitmq_queue = request.rabbitmq_queue or settings.rabbitmq_queue

    # Validate S3 file exists
    if not s3_client.file_exists(request.s3_key, s3_bucket):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{request.s3_key}' not found in bucket '{s3_bucket}'",
        )

    # Declare RabbitMQ queue
    if not rabbitmq_producer.declare_queue(rabbitmq_queue):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to declare RabbitMQ queue '{rabbitmq_queue}'",
        )

    # Add background task
    background_tasks.add_task(
        process_s3_scan_rabbitmq,
        request_id,
        request.s3_key,
        s3_bucket,
        rabbitmq_queue,
    )

    logger.info(f"[{request_id}] Accepted scan request for s3://{s3_bucket}/{request.s3_key} (RabbitMQ)")

    return S3ScanAccepted(
        request_id=request_id,
        status="accepted",
        message=f"Scan request accepted. Result will be sent to RabbitMQ queue '{rabbitmq_queue}'",
    )


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Check application and all service health status.

    Returns status of ClamAV, Redis, S3, Kafka, and RabbitMQ services.
    """
    clamav_ok = clamav_client.ping()

    # Collect service status
    services = {
        "clamav": {
            "enabled": True,
            "connected": clamav_ok,
        },
        "redis": {
            "enabled": True,
            "connected": cache_client.client is not None,
        },
        "s3": {
            "enabled": settings.enable_s3,
            "connected": s3_client.client is not None if settings.enable_s3 else None,
        },
        "kafka": {
            "enabled": settings.enable_kafka,
            "connected": kafka_producer.producer is not None if settings.enable_kafka else None,
        },
        "rabbitmq": {
            "enabled": settings.enable_rabbitmq,
            "connected": rabbitmq_producer.channel is not None if settings.enable_rabbitmq else None,
        },
    }

    # Check overall health
    if clamav_ok:
        return HealthResponse(
            status="healthy",
            message="API and ClamAV are operational",
            services=services,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "message": "ClamAV is not responding",
                "services": services,
            },
        )


@router.get("/version", response_model=VersionResponse)
async def get_version():
    """Get API and ClamAV versions."""
    clamav_version = clamav_client.get_version()

    if clamav_version is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to retrieve ClamAV version",
        )

    return VersionResponse(
        api_version=settings.app_version,
        clamav_version=clamav_version,
    )
