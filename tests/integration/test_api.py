import io
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import FileScanResult


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


class TestRootEndpoint:
    def test_root_returns_api_info(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "endpoints" in data


class TestHealthEndpoint:
    @patch("app.routers.scan.clamav_client")
    def test_health_check_healthy(self, mock_client, client):
        mock_client.ping.return_value = True

        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    @patch("app.routers.scan.clamav_client")
    def test_health_check_unhealthy(self, mock_client, client):
        mock_client.ping.return_value = False

        response = client.get("/api/v1/health")
        assert response.status_code == 503


class TestVersionEndpoint:
    @patch("app.routers.scan.clamav_client")
    def test_version_returns_versions(self, mock_client, client):
        mock_client.get_version.return_value = "ClamAV 1.0.0"

        response = client.get("/api/v1/version")
        assert response.status_code == 200
        data = response.json()
        assert "api_version" in data
        assert "clamav_version" in data
        assert data["clamav_version"] == "ClamAV 1.0.0"

    @patch("app.routers.scan.clamav_client")
    def test_version_unavailable(self, mock_client, client):
        mock_client.get_version.return_value = None

        response = client.get("/api/v1/version")
        assert response.status_code == 503


class TestScanEndpoint:
    @patch("app.routers.scan.clamav_client")
    def test_scan_single_clean_file(self, mock_client, client):
        mock_client.client = MagicMock()
        mock_client.scan_stream.return_value = (
            FileScanResult(
                filename="test.txt",
                size_bytes=1024,
                sha256_hash="abc123",
                status="clean",
                virus_signature=None,
                scan_time_seconds=0.1,
                timestamp=datetime.utcnow(),
            ),
            None,
        )

        files = {"files": ("test.txt", b"clean content", "text/plain")}
        response = client.post("/api/v1/scan", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["total_files"] == 1
        assert data["clean_files"] == 1
        assert data["infected_files"] == 0

    @patch("app.routers.scan.clamav_client")
    def test_scan_infected_file(self, mock_client, client):
        mock_client.client = MagicMock()
        mock_client.scan_stream.return_value = (
            FileScanResult(
                filename="malware.exe",
                size_bytes=2048,
                sha256_hash="def456",
                status="infected",
                virus_signature="Win.Test.EICAR_HDB-1",
                scan_time_seconds=0.2,
                timestamp=datetime.utcnow(),
            ),
            None,
        )

        files = {"files": ("malware.exe", b"infected content", "application/octet-stream")}
        response = client.post("/api/v1/scan", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["infected_files"] == 1
        assert data["results"][0]["virus_signature"] == "Win.Test.EICAR_HDB-1"

    @patch("app.routers.scan.clamav_client")
    def test_scan_multiple_files(self, mock_client, client):
        mock_client.client = MagicMock()
        mock_client.scan_stream.return_value = (
            FileScanResult(
                filename="test.txt",
                size_bytes=1024,
                sha256_hash="abc123",
                status="clean",
                virus_signature=None,
                scan_time_seconds=0.1,
                timestamp=datetime.utcnow(),
            ),
            None,
        )

        files = [
            ("files", ("file1.txt", b"content 1", "text/plain")),
            ("files", ("file2.txt", b"content 2", "text/plain")),
            ("files", ("file3.txt", b"content 3", "text/plain")),
        ]
        response = client.post("/api/v1/scan", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["total_files"] == 3

    @patch("app.routers.scan.clamav_client")
    def test_scan_no_files(self, mock_client, client):
        mock_client.client = MagicMock()

        response = client.post("/api/v1/scan")
        assert response.status_code == 422  # Validation error

    @patch("app.routers.scan.clamav_client")
    def test_scan_service_unavailable(self, mock_client, client):
        mock_client.client = None

        files = {"files": ("test.txt", b"content", "text/plain")}
        response = client.post("/api/v1/scan", files=files)

        assert response.status_code == 503

    @patch("app.routers.scan.clamav_client")
    @patch("app.routers.scan.settings")
    def test_scan_too_many_files(self, mock_settings, mock_client, client):
        mock_client.client = MagicMock()
        mock_settings.max_files = 2

        files = [
            ("files", ("file1.txt", b"content 1", "text/plain")),
            ("files", ("file2.txt", b"content 2", "text/plain")),
            ("files", ("file3.txt", b"content 3", "text/plain")),
        ]
        response = client.post("/api/v1/scan", files=files)

        assert response.status_code == 400
        assert "Maximum" in response.json()["detail"]

    @patch("app.routers.scan.clamav_client")
    def test_scan_with_error(self, mock_client, client):
        mock_client.client = MagicMock()
        mock_client.scan_stream.return_value = (
            FileScanResult(
                filename="error.bin",
                size_bytes=0,
                sha256_hash="",
                status="error",
                virus_signature=None,
                scan_time_seconds=0,
                timestamp=datetime.utcnow(),
            ),
            "Scan error occurred",
        )

        files = {"files": ("error.bin", b"content", "application/octet-stream")}
        response = client.post("/api/v1/scan", files=files)

        assert response.status_code == 200
        data = response.json()
        assert data["error_files"] == 1
