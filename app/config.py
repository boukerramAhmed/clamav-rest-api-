from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings from environment variables"""

    # ClamAV Configuration
    clamav_type: str = "unix"  # "unix" or "tcp"
    clamav_unix_socket: str = "/var/run/clamav/clamd.ctl"
    clamav_host: str = "localhost"
    clamav_port: int = 3310
    clamav_timeout: int = 30

    # File Upload Configuration
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    max_files: int = 10
    upload_timeout: int = 300

    # Redis Cache Configuration
    redis_host: str = "localhost"
    redis_port: int = 6379
    cache_ttl: int = 86400  # 24 hours
    cache_enabled: bool = True

    # S3 Configuration (MinIO)
    s3_endpoint: str = "http://localhost:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket: str = "scans"

    # Kafka Configuration (Redpanda)
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic: str = "scan-results"

    # RabbitMQ Configuration
    rabbitmq_host: str = "localhost"
    rabbitmq_port: int = 5672
    rabbitmq_user: str = "guest"
    rabbitmq_password: str = "guest"
    rabbitmq_queue: str = "scan-results"

    # Service Enable/Disable Flags
    enable_kafka: bool = False
    enable_rabbitmq: bool = False
    enable_s3: bool = False

    # Application Configuration
    app_name: str = "ClamAV API"
    app_version: str = "1.0.0"
    debug: bool = False

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
