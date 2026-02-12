from datetime import datetime

from app.models import FileScanResult, HealthResponse, ScanResponse, VersionResponse


class TestFileScanResult:
    def test_create_clean_result(self):
        result = FileScanResult(
            filename="test.txt",
            size_bytes=1024,
            sha256_hash="abc123",
            status="clean",
            virus_signature=None,
            scan_time_seconds=0.5,
            timestamp=datetime.utcnow(),
        )
        assert result.filename == "test.txt"
        assert result.size_bytes == 1024
        assert result.status == "clean"
        assert result.virus_signature is None

    def test_create_infected_result(self):
        result = FileScanResult(
            filename="malware.exe",
            size_bytes=2048,
            sha256_hash="def456",
            status="infected",
            virus_signature="Win.Test.EICAR_HDB-1",
            scan_time_seconds=0.3,
            timestamp=datetime.utcnow(),
        )
        assert result.status == "infected"
        assert result.virus_signature == "Win.Test.EICAR_HDB-1"

    def test_create_error_result(self):
        result = FileScanResult(
            filename="broken.bin",
            size_bytes=0,
            sha256_hash="",
            status="error",
            virus_signature=None,
            scan_time_seconds=0,
            timestamp=datetime.utcnow(),
        )
        assert result.status == "error"


class TestScanResponse:
    def test_create_scan_response(self):
        result = FileScanResult(
            filename="test.txt",
            size_bytes=1024,
            sha256_hash="abc123",
            status="clean",
            virus_signature=None,
            scan_time_seconds=0.5,
            timestamp=datetime.utcnow(),
        )
        response = ScanResponse(
            total_files=1,
            clean_files=1,
            infected_files=0,
            error_files=0,
            results=[result],
        )
        assert response.total_files == 1
        assert response.clean_files == 1
        assert len(response.results) == 1

    def test_scan_response_with_multiple_files(self):
        results = [
            FileScanResult(
                filename=f"file{i}.txt",
                size_bytes=1024,
                sha256_hash=f"hash{i}",
                status="clean",
                virus_signature=None,
                scan_time_seconds=0.1,
                timestamp=datetime.utcnow(),
            )
            for i in range(3)
        ]
        response = ScanResponse(
            total_files=3,
            clean_files=3,
            infected_files=0,
            error_files=0,
            results=results,
        )
        assert response.total_files == 3
        assert len(response.results) == 3


class TestHealthResponse:
    def test_healthy_response(self):
        response = HealthResponse(status="healthy", message="All systems operational")
        assert response.status == "healthy"

    def test_unhealthy_response(self):
        response = HealthResponse(status="unhealthy", message="ClamAV not responding")
        assert response.status == "unhealthy"


class TestVersionResponse:
    def test_version_response(self):
        response = VersionResponse(api_version="1.0.0", clamav_version="ClamAV 1.2.0")
        assert response.api_version == "1.0.0"
        assert response.clamav_version == "ClamAV 1.2.0"
