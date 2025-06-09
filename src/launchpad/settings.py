"""
Settings and configuration for the Launchpad service.
"""

from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Main settings for the Launchpad service."""

    # Server configuration
    host: str = Field(default="127.0.0.1", env="LAUNCHPAD_HOST")  # Default to localhost only
    port: int = Field(default=1218, env="LAUNCHPAD_PORT")
    debug: bool = Field(default=False, env="DEBUG")

    # Security configuration
    allowed_hosts: List[str] = Field(default=["127.0.0.1", "localhost", "launchpad"], env="ALLOWED_HOSTS")
    internal_networks: List[str] = Field(
        default=["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12"], env="INTERNAL_NETWORKS"
    )
    require_internal_auth: bool = Field(default=True, env="REQUIRE_INTERNAL_AUTH")
    internal_auth_token: Optional[str] = Field(default=None, env="INTERNAL_AUTH_TOKEN")

    # Redis configuration
    redis_host: str = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_db: int = Field(default=0, env="REDIS_DB")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")

    # Kafka configuration
    kafka_brokers: List[str] = Field(default=["localhost:9092"], env="DEFAULT_BROKERS")
    kafka_consumer_group: str = Field(default="launchpad", env="KAFKA_CONSUMER_GROUP")

    # Sentry configuration
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    sentry_environment: str = Field(default="development", env="SENTRY_ENVIRONMENT")

    # Analysis configuration
    max_file_size: int = Field(default=1024 * 1024 * 1024, env="MAX_FILE_SIZE")  # 1GB
    temp_dir: str = Field(default="/tmp/launchpad", env="TEMP_DIR")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    class Config:
        env_file = ".env"
        case_sensitive = False

        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> any:
            if field_name in ["kafka_brokers", "allowed_hosts", "internal_networks"]:
                return raw_val.split(",")
            return cls.json_loads(raw_val)


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings
