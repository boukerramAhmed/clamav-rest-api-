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


class VersionResponse(BaseModel):
    """Version information response"""

    api_version: str = Field(..., description="API version")
    clamav_version: str = Field(..., description="ClamAV version")
