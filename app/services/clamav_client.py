import hashlib
import io
import logging
from datetime import datetime
from time import time
from typing import BinaryIO, Optional, Tuple

import clamd

from app.config import settings
from app.models import FileScanResult

logger = logging.getLogger(__name__)


class ClamAVClient:
    """Wrapper around clamd for ClamAV interactions"""

    def __init__(self):
        self.client: Optional[clamd.ClamD] = None
        self.connection_type = settings.clamav_type

    def connect(self) -> bool:
        """
        Establish connection to ClamAV daemon.

        Returns True if successful, False otherwise.
        """
        try:
            if self.connection_type == "unix":
                self.client = clamd.ClamdUnixSocket(filename=settings.clamav_unix_socket)
            elif self.connection_type == "tcp":
                self.client = clamd.ClamdNetworkSocket(
                    host=settings.clamav_host, port=settings.clamav_port
                )
            else:
                logger.error(f"Unknown connection type: {self.connection_type}")
                return False

            # Test the connection
            self.ping()
            logger.info(
                f"Connected to ClamAV via {self.connection_type}: "
                f"version {self.get_version()}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to ClamAV: {e}")
            self.client = None
            return False

    def ping(self) -> bool:
        """
        Ping ClamAV daemon to check if it's alive.

        Returns True if alive, False otherwise.
        """
        if not self.client:
            return False

        try:
            response = self.client.ping()
            return response == "PONG"
        except Exception as e:
            logger.error(f"Ping failed: {e}")
            return False

    def get_version(self) -> Optional[str]:
        """Get ClamAV version string."""
        if not self.client:
            return None

        try:
            return self.client.version()
        except Exception as e:
            logger.error(f"Failed to get ClamAV version: {e}")
            return None

    def scan_stream(
        self, file_obj: BinaryIO, filename: str
    ) -> Tuple[FileScanResult, Optional[str]]:
        """
        Scan a file from a file-like object.

        Args:
            file_obj: File-like object containing file content
            filename: Original filename for the result

        Returns:
            Tuple of (FileScanResult, error_message)
        """
        if not self.client:
            return (
                FileScanResult(
                    filename=filename,
                    size_bytes=0,
                    sha256_hash="",
                    status="error",
                    virus_signature=None,
                    scan_time_seconds=0,
                    timestamp=datetime.utcnow(),
                ),
                "ClamAV client not connected",
            )

        start_time = time()
        sha256_hash = ""
        file_size = 0
        status = "clean"
        virus_signature = None
        error_message = None

        try:
            # Read file content and calculate hash
            file_content = file_obj.read()
            file_size = len(file_content)

            # Calculate SHA256
            sha256_hash = hashlib.sha256(file_content).hexdigest()

            # Scan the file
            stream = io.BytesIO(file_content)
            scan_result = self.client.instream(stream)

            if scan_result is None:
                # File is clean
                status = "clean"
            else:
                # File is infected
                status = "infected"
                # Extract virus signature from result
                # clamd returns: {'path': (status, virus_name)}
                if isinstance(scan_result, dict):
                    for path, (detected_status, virus_name) in scan_result.items():
                        if virus_name:
                            virus_signature = virus_name
                            break

        except Exception as e:
            error_message = str(e)
            status = "error"
            logger.error(f"Error scanning file {filename}: {e}")

        scan_time = time() - start_time

        result = FileScanResult(
            filename=filename,
            size_bytes=file_size,
            sha256_hash=sha256_hash,
            status=status,
            virus_signature=virus_signature,
            scan_time_seconds=round(scan_time, 2),
            timestamp=datetime.utcnow(),
        )

        return result, error_message

    def disconnect(self):
        """Disconnect from ClamAV daemon."""
        self.client = None
        logger.info("Disconnected from ClamAV")


# Global client instance
clamav_client = ClamAVClient()
