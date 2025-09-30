"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import os
import signal
import threading

from dataclasses import dataclass
from typing import Any

from launchpad.sentry_client import SentryClient
from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import NullStatsd, StatsdInterface, get_statsd

from .kafka import LaunchpadKafkaConsumer, create_kafka_consumer
from .sentry_sdk_init import initialize_sentry_sdk
from .server import LaunchpadServer, get_server_config

logger = get_logger(__name__)


class LaunchpadService:
    """Main service that orchestrates HTTP server and Kafka consumer."""

    def __init__(self, statsd: StatsdInterface | None = None) -> None:
        self.server: LaunchpadServer | None = None
        self.kafka: LaunchpadKafkaConsumer | None = None
        self._kafka_task: asyncio.Future[Any] | None = None
        self._statsd = statsd or NullStatsd()
        self._healthcheck_file: str | None = None
        self._service_config: ServiceConfig | None = None
        self._sentry_client: SentryClient | None = None

    async def setup(self) -> None:
        """Set up the service components."""
        initialize_sentry_sdk()
        self._service_config = get_service_config()
        self._sentry_client = SentryClient(base_url=self._service_config.sentry_base_url)

        server_config = get_server_config()
        self.server = LaunchpadServer(
            self.is_healthy,
            host=server_config.host,
            port=server_config.port,
            statsd=self._statsd,
        )

        self.kafka = create_kafka_consumer()

        logger.info("Service components initialized")

    async def start(self) -> None:
        """Start all service components."""
        if not self.server or not self.kafka:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        logger.info("Starting Launchpad service...")

        shutdown_event = asyncio.Event()

        def signal_handler(signum: int) -> None:
            if shutdown_event.is_set():
                logger.info(f"Received signal {signum} during shutdown, forcing exit...")
                # Force exit if we get a second signal
                os._exit(1)
                return
            logger.info(f"Received signal {signum}, initiating shutdown...")
            shutdown_event.set()

        assert threading.current_thread() is threading.main_thread()
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, signal_handler, signal.SIGTERM)
        loop.add_signal_handler(signal.SIGINT, signal_handler, signal.SIGINT)

        await self.kafka.start()
        await self.server.start()

        logger.info("Launchpad service started successfully")

        try:
            await shutdown_event.wait()
        finally:
            logger.info("Cleaning up service resources...")
            awaitable_stop_server = None
            awaitable_stop_kafka = None
            if self.kafka:
                awaitable_stop_kafka = self.kafka.stop()
            if self.server:
                awaitable_stop_server = self.server.stop()
            if awaitable_stop_kafka:
                await awaitable_stop_kafka
            if awaitable_stop_server:
                await awaitable_stop_server
            logger.info("...service cleanup completed")

    def is_healthy(self) -> bool:
        """Get overall service health status."""
        is_server_healthy = self.server.is_healthy()
        is_kafka_healthy = self.kafka.is_healthy()
        return is_server_healthy and is_kafka_healthy


@dataclass
class ServiceConfig:
    """Service configuration data."""

    sentry_base_url: str
    projects_to_skip: list[str]


def get_service_config() -> ServiceConfig:
    """Get service configuration from environment."""
    sentry_base_url = os.getenv("SENTRY_BASE_URL")
    projects_to_skip_str = os.getenv("PROJECT_IDS_TO_SKIP")
    projects_to_skip = projects_to_skip_str.split(",") if projects_to_skip_str else []

    if sentry_base_url is None:
        sentry_base_url = "http://getsentry.default"

    return ServiceConfig(
        sentry_base_url=sentry_base_url,
        projects_to_skip=projects_to_skip,
    )


async def run_service() -> None:
    """Run the Launchpad service."""
    statsd = get_statsd()
    service = LaunchpadService(statsd)
    await service.setup()
    await service.start()
