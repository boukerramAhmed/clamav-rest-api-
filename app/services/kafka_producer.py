import asyncio
import json
import logging
from typing import Any, Optional, Set

from aiokafka import AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient

from app.config import settings

logger = logging.getLogger(__name__)


class TopicNotFoundError(Exception):
    """Raised when a Kafka topic does not exist"""
    pass


class KafkaProducerClient:
    """Kafka producer client for sending scan results"""

    def __init__(self):
        self.producer: Optional[AIOKafkaProducer] = None
        self.admin_client: Optional[AIOKafkaAdminClient] = None
        self._topics_cache: Set[str] = set()

    async def connect(self) -> bool:
        """
        Establish connection to Kafka.

        Returns True if successful, False otherwise.
        """
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap_servers,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            )
            await self.producer.start()

            # Initialize admin client for topic validation
            self.admin_client = AIOKafkaAdminClient(
                bootstrap_servers=settings.kafka_bootstrap_servers,
            )
            await self.admin_client.start()

            # Refresh topics cache
            await self._refresh_topics_cache()

            logger.info(f"Connected to Kafka at {settings.kafka_bootstrap_servers}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            self.producer = None
            self.admin_client = None
            return False

    async def _refresh_topics_cache(self):
        """Refresh the cached list of topics."""
        if self.admin_client:
            try:
                topics = await self.admin_client.list_topics()
                self._topics_cache = set(topics)
                logger.debug(f"Refreshed topics cache: {self._topics_cache}")
            except Exception as e:
                logger.error(f"Failed to refresh topics cache: {e}")

    async def topic_exists(self, topic: str) -> bool:
        """
        Check if a Kafka topic exists.

        Args:
            topic: Topic name to check

        Returns:
            True if topic exists, False otherwise
        """
        # First check cache
        if topic in self._topics_cache:
            return True

        # Refresh cache and check again
        await self._refresh_topics_cache()
        return topic in self._topics_cache

    async def disconnect(self):
        """Disconnect from Kafka."""
        if self.admin_client:
            await self.admin_client.close()
            self.admin_client = None
        if self.producer:
            await self.producer.stop()
            self.producer = None
        self._topics_cache.clear()
        logger.info("Disconnected from Kafka")

    async def send_result(self, topic: str, result: dict[str, Any], key: Optional[str] = None) -> bool:
        """
        Send scan result to Kafka topic.

        Args:
            topic: Kafka topic name
            result: Scan result dictionary
            key: Optional message key for partitioning (uses request_id if available)

        Returns:
            True if successful

        Raises:
            TopicNotFoundError: If the topic does not exist
        """
        if not self.producer:
            logger.error("Kafka producer not connected")
            return False

        # Validate topic exists
        if not await self.topic_exists(topic):
            raise TopicNotFoundError(f"Kafka topic '{topic}' does not exist")

        # Use request_id as key if not provided
        if key is None:
            key = result.get("request_id", "default")

        # Encode key if it's a string
        message_key = key.encode("utf-8") if isinstance(key, str) else key

        try:
            await self.producer.send_and_wait(topic, value=result, key=message_key)
            logger.info(f"Sent scan result to Kafka topic {topic} with key {key}")
            return True
        except Exception as e:
            logger.error(f"Failed to send to Kafka topic {topic}: {e}")
            return False


# Global Kafka producer instance
kafka_producer = KafkaProducerClient()
