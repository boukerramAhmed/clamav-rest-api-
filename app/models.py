from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class FileScanResult(BaseModel):
    """Result of scanning a single file"""

    filename: str = Field(..., description="Original filename")
    size_bytes: int = Field(..., description="File size in bytes")
    sha256_hash: str = Field(..., description="SHA256 hash of the file")
    status: str = Field(..., description="Scan status: clean, infected, or error")
    virus_signature: Optional[str] = Field(None, description="Virus signature if infected")
    scan_time_seconds: float = Field(..., description="Time taken to scan in seconds")
    timestamp: datetime = Field(..., description="Scan timestamp")
    cached: bool = Field(False, description="Whether result was from cache")

    class Config:
        json_schema_extra = {
            "example": {
                "filename": "document.pdf",
                "size_bytes": 102400,
                "sha256_hash": "abc123def456...",
                "status": "clean",
                "virus_signature": None,
                "scan_time_seconds": 0.15,
                "timestamp": "2026-01-31T10:30:00Z",
            }
        }


class ScanResponse(BaseModel):
    """Response from file scan endpoint"""

    total_files: int = Field(..., description="Total number of files scanned")
    clean_files: int = Field(..., description="Number of clean files")
    infected_files: int = Field(..., description="Number of infected files")
    error_files: int = Field(..., description="Number of files with scan errors")
    results: List[FileScanResult] = Field(..., description="Detailed results for each file")

    class Config:
        json_schema_extra = {
            "example": {
                "total_files": 2,
                "clean_files": 1,
                "infected_files": 1,
                "error_files": 0,
                "results": [
                    {
                        "filename": "file1.pdf",
                        "size_bytes": 102400,
                        "sha256_hash": "abc123...",
                        "status": "clean",
                        "virus_signature": None,
                        "scan_time_seconds": 0.15,
                        "timestamp": "2026-01-31T10:30:00Z",
                    },
                    {
                        "filename": "file2.zip",
                        "size_bytes": 204800,
                        "sha256_hash": "def456...",
                        "status": "infected",
                        "virus_signature": "Win.Test.EICAR_HDB-1",
                        "scan_time_seconds": 0.23,
                        "timestamp": "2026-01-31T10:30:00Z",
                    },
                ],
            }
        }


class HealthResponse(BaseModel):
    """Health check response"""

    status: str = Field(..., description="Health status: healthy or unhealthy")
    message: str = Field(..., description="Status message")
    services: Optional[dict] = Field(None, description="Status of individual services")


class VersionResponse(BaseModel):
    """Version information response"""

    api_version: str = Field(..., description="API version")
    clamav_version: str = Field(..., description="ClamAV version")


class PresignedUrlScanRequest(BaseModel):
    """Request to scan a file from a presigned S3 URL"""

    presigned_url: str = Field(..., description="Presigned URL of the S3 object")

    class Config:
        json_schema_extra = {
            "example": {
                "presigned_url": "https://minio:9000/bucket/file.pdf?X-Amz-Algorithm=..."
            }
        }


class S3ScanRequest(BaseModel):
    """Request to scan a file from S3"""

    s3_key: str = Field(..., description="S3 object key of the file to scan")
    kafka_topic: Optional[str] = Field(None, description="Kafka topic to send scan result to (uses default if not specified)")
    s3_bucket: Optional[str] = Field(None, description="S3 bucket name (uses default if not specified)")

    class Config:
        json_schema_extra = {
            "example": {
                "s3_key": "uploads/document.pdf",
                "kafka_topic": "scan-results",
            }
        }


class S3RabbitMQScanRequest(BaseModel):
    """Request to scan a file from S3 and publish result to RabbitMQ"""

    s3_key: str = Field(..., description="S3 object key of the file to scan")
    rabbitmq_queue: Optional[str] = Field(None, description="RabbitMQ queue to send scan result to (uses default if not specified)")
    s3_bucket: Optional[str] = Field(None, description="S3 bucket name (uses default if not specified)")

    class Config:
        json_schema_extra = {
            "example": {
                "s3_key": "uploads/document.pdf",
                "rabbitmq_queue": "scan-results",
            }
        }


class S3ScanAccepted(BaseModel):
    """Response when S3 scan request is accepted"""

    request_id: str = Field(..., description="Unique request ID for tracking")
    status: str = Field(default="accepted", description="Request status")
    message: str = Field(..., description="Status message")

    class Config:
        json_schema_extra = {
            "example": {
                "request_id": "abc123-def456-789",
                "status": "accepted",
                "message": "Scan request accepted. Result will be sent to Kafka topic 'scan-results'",
            }
        }
