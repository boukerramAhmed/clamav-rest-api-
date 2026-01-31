import logging
from typing import List

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.config import settings
from app.models import HealthResponse, ScanResponse, VersionResponse
from app.services.clamav_client import clamav_client

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
        # Validate file size
        file_content = await file.read()
        if len(file_content) > settings.max_file_size:
            results.append({
                "filename": file.filename or "unknown",
                "size_bytes": len(file_content),
                "sha256_hash": "",
                "status": "error",
                "virus_signature": None,
                "scan_time_seconds": 0,
                "timestamp": None,  # Will be set by model
            })
            error_count += 1
            logger.warning(
                f"File {file.filename} exceeds max size of {settings.max_file_size} bytes"
            )
            continue

        # Reset file pointer
        await file.seek(0)

        # Scan the file
        try:
            result, error = clamav_client.scan_stream(file.file, file.filename or "unknown")

            if error:
                error_count += 1
                logger.error(f"Scan error for {file.filename}: {error}")
            elif result.status == "clean":
                clean_count += 1
            elif result.status == "infected":
                infected_count += 1

            results.append(result)

        except Exception as e:
            error_count += 1
            print(e)
            logger.info(e)
            logger.error(f"Unexpected error scanning {file.filename}: {e}")
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


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Check application and ClamAV health status.

    Returns healthy if both the API and ClamAV are operational.
    """
    if clamav_client.ping():
        return HealthResponse(
            status="healthy",
            message="API and ClamAV are operational",
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "message": "ClamAV is not responding",
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
