import json
import logging
from typing import Any, Dict

import pika
from pika.exceptions import AMQPError

from app.config import settings

logger = logging.getLogger(__name__)


class RabbitMQProducer:
    """RabbitMQ producer for publishing scan results"""

    def __init__(self):
        self.connection = None
        self.channel = None

    def connect(self) -> bool:
        """
        Establish connection to RabbitMQ.

        Returns True if successful, False otherwise.
        """
        try:
            credentials = pika.PlainCredentials(
                settings.rabbitmq_user,
                settings.rabbitmq_password,
            )
            self.connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=settings.rabbitmq_host,
                    port=settings.rabbitmq_port,
                    credentials=credentials,
                    connection_attempts=3,
                    retry_delay=2,
                )
            )
            self.channel = self.connection.channel()
            logger.info(
                f"Connected to RabbitMQ at {settings.rabbitmq_host}:{settings.rabbitmq_port}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            self.connection = None
            self.channel = None
            return False

    def disconnect(self):
        """Disconnect from RabbitMQ."""
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            logger.info("Disconnected from RabbitMQ")

    def declare_queue(self, queue_name: str = None) -> bool:
        """
        Declare a queue (creates it if it doesn't exist).

        Args:
            queue_name: Queue name (defaults to configured queue)

        Returns:
            True if successful, False otherwise
        """
        if not self.channel:
            logger.error("RabbitMQ channel not connected")
            return False

        queue_name = queue_name or settings.rabbitmq_queue

        try:
            self.channel.queue_declare(queue=queue_name, durable=True)
            logger.info(f"Declared queue: {queue_name}")
            return True
        except AMQPError as e:
            logger.error(f"Failed to declare queue {queue_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error declaring queue {queue_name}: {e}")
            return False

    async def send_result(
        self, result: Dict[str, Any], queue_name: str = None
    ) -> bool:
        """
        Publish scan result to RabbitMQ queue.

        Args:
            result: Scan result dictionary
            queue_name: Queue name (defaults to configured queue)

        Returns:
            True if successful, False otherwise
        """
        if not self.channel:
            logger.error("RabbitMQ channel not connected")
            return False

        queue_name = queue_name or settings.rabbitmq_queue

        try:
            message = json.dumps(result)
            self.channel.basic_publish(
                exchange="",
                routing_key=queue_name,
                body=message,
                properties=pika.BasicProperties(
                    delivery_mode=pika.DeliveryMode.Persistent,
                    content_type="application/json",
                ),
            )
            logger.info(f"Published scan result to queue: {queue_name}")
            return True
        except AMQPError as e:
            logger.error(f"Failed to publish message to {queue_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error publishing to {queue_name}: {e}")
            return False


# Global RabbitMQ producer instance
rabbitmq_producer = RabbitMQProducer()
