import json
import logging
from datetime import datetime
from typing import Optional

import redis

from app.config import settings
from app.models import FileScanResult

logger = logging.getLogger(__name__)


class CacheClient:
    """Redis cache client for storing scan results"""

    def __init__(self):
        self.client: Optional[redis.Redis] = None

    def connect(self) -> bool:
        """
        Establish connection to Redis.

        Returns True if successful, False otherwise.
        """
        if not settings.cache_enabled:
            logger.info("Cache is disabled")
            return False

        try:
            self.client = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                decode_responses=True,
            )
            self.client.ping()
            logger.info(
                f"Connected to Redis at {settings.redis_host}:{settings.redis_port}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.client = None
            return False

    def disconnect(self):
        """Disconnect from Redis."""
        if self.client:
            self.client.close()
            self.client = None
            logger.info("Disconnected from Redis")

    def get_scan_result(self, sha256_hash: str) -> Optional[FileScanResult]:
        """
        Get cached scan result by SHA256 hash.

        Returns FileScanResult if found, None otherwise.
        """
        if not self.client or not settings.cache_enabled:
            return None

        try:
            key = f"scan:{sha256_hash}"
            data = self.client.get(key)
            if data:
                result_dict = json.loads(data)
                result_dict["timestamp"] = datetime.fromisoformat(
                    result_dict["timestamp"]
                )
                return FileScanResult(**result_dict)
            return None
        except Exception as e:
            logger.error(f"Failed to get cached result for {sha256_hash}: {e}")
            return None

    def set_scan_result(self, sha256_hash: str, result: FileScanResult) -> bool:
        """
        Cache scan result by SHA256 hash.

        Returns True if successful, False otherwise.
        """
        if not self.client or not settings.cache_enabled:
            return False

        try:
            key = f"scan:{sha256_hash}"
            data = result.model_dump()
            data["timestamp"] = data["timestamp"].isoformat()
            self.client.setex(key, settings.cache_ttl, json.dumps(data))
            logger.debug(f"Cached scan result for {sha256_hash}")
            return True
        except Exception as e:
            logger.error(f"Failed to cache result for {sha256_hash}: {e}")
            return False


# Global cache client instance
cache_client = CacheClient()
