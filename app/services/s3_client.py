import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from app.config import settings

logger = logging.getLogger(__name__)


class S3Client:
    """S3 client for downloading files from MinIO/S3"""

    def __init__(self):
        self.client = None

    def connect(self) -> bool:
        """
        Establish connection to S3/MinIO.

        Returns True if successful, False otherwise.
        """
        try:
            self.client = boto3.client(
                "s3",
                endpoint_url=settings.s3_endpoint,
                aws_access_key_id=settings.s3_access_key,
                aws_secret_access_key=settings.s3_secret_key,
            )
            # Test connection by listing buckets
            self.client.list_buckets()
            logger.info(f"Connected to S3 at {settings.s3_endpoint}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to S3: {e}")
            self.client = None
            return False

    def disconnect(self):
        """Disconnect from S3."""
        self.client = None
        logger.info("Disconnected from S3")

    def file_exists(self, key: str, bucket: Optional[str] = None) -> bool:
        """
        Check if a file exists in S3 bucket.

        Args:
            key: S3 object key
            bucket: Bucket name (defaults to configured bucket)

        Returns:
            True if file exists, False otherwise
        """
        if not self.client:
            logger.error("S3 client not connected")
            return False

        bucket = bucket or settings.s3_bucket

        try:
            self.client.head_object(Bucket=bucket, Key=key)
            logger.info(f"File {key} exists in bucket {bucket}")
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "404" or error_code == "NotFound":
                logger.warning(f"File {key} not found in bucket {bucket}")
            else:
                logger.error(
                    f"Error checking file {key} in {bucket}: {error_code} - {e}"
                )
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking file {key}: {e}")
            return False

    def download_file(self, key: str, bucket: Optional[str] = None) -> Optional[bytes]:
        """
        Download file from S3 bucket.

        Args:
            key: S3 object key
            bucket: Bucket name (defaults to configured bucket)

        Returns:
            File content as bytes, or None if failed
        """
        if not self.client:
            logger.error("S3 client not connected")
            return None

        bucket = bucket or settings.s3_bucket

        try:
            response = self.client.get_object(Bucket=bucket, Key=key)
            content = response["Body"].read()
            logger.info(
                f"Downloaded file {key} from bucket {bucket} ({len(content)} bytes)"
            )
            return content
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Failed to download {key} from {bucket}: {error_code} - {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error downloading {key}: {e}")
            return None


# Global S3 client instance
s3_client = S3Client()
