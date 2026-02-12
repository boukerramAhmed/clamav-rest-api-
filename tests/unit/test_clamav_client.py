import io
from unittest.mock import MagicMock, patch

from app.services.clamav_client import ClamAVClient


class TestClamAVClient:
    def test_init(self):
        client = ClamAVClient()
        assert client.client is None

    @patch("app.services.clamav_client.clamd")
    def test_connect_tcp_success(self, mock_clamd):
        mock_clamd_instance = MagicMock()
        mock_clamd_instance.ping.return_value = "PONG"
        mock_clamd_instance.version.return_value = "ClamAV 1.0.0"
        mock_clamd.ClamD.return_value = mock_clamd_instance

        with patch("app.services.clamav_client.settings") as mock_settings:
            mock_settings.clamav_type = "tcp"
            mock_settings.clamav_host = "localhost"
            mock_settings.clamav_port = 3310

            client = ClamAVClient()
            client.connection_type = "tcp"
            result = client.connect()

            assert result is True
            assert client.client is not None

    @patch("app.services.clamav_client.clamd")
    def test_connect_unix_success(self, mock_clamd):
        mock_clamd_instance = MagicMock()
        mock_clamd_instance.ping.return_value = "PONG"
        mock_clamd_instance.version.return_value = "ClamAV 1.0.0"
        mock_clamd.ClamD.return_value = mock_clamd_instance

        with patch("app.services.clamav_client.settings") as mock_settings:
            mock_settings.clamav_type = "unix"
            mock_settings.clamav_unix_socket = "/var/run/clamav/clamd.ctl"

            client = ClamAVClient()
            client.connection_type = "unix"
            result = client.connect()

            assert result is True

    def test_connect_unknown_type(self):
        client = ClamAVClient()
        client.connection_type = "unknown"
        result = client.connect()
        assert result is False

    def test_ping_no_client(self):
        client = ClamAVClient()
        assert client.ping() is False

    def test_ping_success(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.ping.return_value = "PONG"
        assert client.ping() is True

    def test_ping_failure(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.ping.return_value = "ERROR"
        assert client.ping() is False

    def test_ping_exception(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.ping.side_effect = Exception("Connection error")
        assert client.ping() is False

    def test_get_version_no_client(self):
        client = ClamAVClient()
        assert client.get_version() is None

    def test_get_version_success(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.version.return_value = "ClamAV 1.0.0"
        assert client.get_version() == "ClamAV 1.0.0"

    def test_get_version_exception(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.version.side_effect = Exception("Error")
        assert client.get_version() is None

    def test_scan_stream_no_client(self):
        client = ClamAVClient()
        file_obj = io.BytesIO(b"test content")
        result, error = client.scan_stream(file_obj, "test.txt")

        assert result.status == "error"
        assert error == "ClamAV client not connected"

    def test_scan_stream_clean_file(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.instream.return_value = None  # None means clean

        file_obj = io.BytesIO(b"clean file content")
        result, error = client.scan_stream(file_obj, "clean.txt")

        assert result.status == "clean"
        assert result.filename == "clean.txt"
        assert result.virus_signature is None
        assert error is None

    def test_scan_stream_infected_file(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.instream.return_value = {
            "stream": ("FOUND", "Win.Test.EICAR_HDB-1")
        }

        file_obj = io.BytesIO(b"infected content")
        result, error = client.scan_stream(file_obj, "malware.exe")

        assert result.status == "infected"
        assert result.virus_signature == "Win.Test.EICAR_HDB-1"
        assert error is None

    def test_scan_stream_exception(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.instream.side_effect = Exception("Scan error")

        file_obj = io.BytesIO(b"some content")
        result, error = client.scan_stream(file_obj, "file.txt")

        assert result.status == "error"
        assert error == "Scan error"

    def test_scan_stream_calculates_hash(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.client.instream.return_value = None

        content = b"test content for hashing"
        file_obj = io.BytesIO(content)
        result, _ = client.scan_stream(file_obj, "test.txt")

        # SHA256 of "test content for hashing"
        import hashlib

        expected_hash = hashlib.sha256(content).hexdigest()
        assert result.sha256_hash == expected_hash

    def test_disconnect(self):
        client = ClamAVClient()
        client.client = MagicMock()
        client.disconnect()
        assert client.client is None
