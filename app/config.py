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

    # Application Configuration
    app_name: str = "ClamAV API"
    app_version: str = "1.0.0"
    debug: bool = False

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
