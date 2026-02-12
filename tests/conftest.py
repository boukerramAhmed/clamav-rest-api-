import io
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.clamav_client import ClamAVClient


@pytest.fixture
def test_client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def mock_clamav_client():
    """Create a mock ClamAV client."""
    client = MagicMock(spec=ClamAVClient)
    client.client = MagicMock()
    client.ping.return_value = True
    client.get_version.return_value = "ClamAV 1.0.0"
    return client


@pytest.fixture
def sample_clean_file():
    """Create a sample clean file for testing."""
    content = b"This is a clean test file content."
    return io.BytesIO(content)


@pytest.fixture
def sample_eicar_file():
    """
    Create the EICAR test file - a standard antivirus test signature.
    This is NOT a real virus, it's an industry-standard test pattern.
    """
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    return io.BytesIO(eicar)


@pytest.fixture
def large_file():
    """Create a file larger than the max allowed size."""
    # 101 MB file (default max is 100 MB)
    content = b"x" * (101 * 1024 * 1024)
    return io.BytesIO(content)
