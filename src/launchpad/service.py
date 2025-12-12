"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import os
import signal
import threading

from dataclasses import dataclass

from launchpad.sentry_client import SentryClient
from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import NullStatsd, StatsdInterface, get_statsd

from .kafka import LaunchpadKafkaConsumer, create_kafka_consumer
from .sentry_sdk_init import initialize_sentry_sdk
from .server import LaunchpadServer, get_server_config

logger = get_logger(__name__)


class LaunchpadService:
    """Main service that orchestrates HTTP server and Kafka consumer.

    The HTTP server runs in a background thread with its own event loop,
    while the Kafka consumer runs in the main thread (required for signal handlers).
    """

    def __init__(self, statsd: StatsdInterface | None = None) -> None:
        self.server: LaunchpadServer | None = None
        self.kafka: LaunchpadKafkaConsumer | None = None
        self._server_thread: threading.Thread | None = None
        self._server_loop: asyncio.AbstractEventLoop | None = None
        self._statsd = statsd or NullStatsd()
        self._healthcheck_file: str | None = None
        self._service_config: ServiceConfig | None = None
        self._sentry_client: SentryClient | None = None
        self._shutdown_requested = False

    def setup(self) -> None:
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

    def start(self) -> None:
        if not self.server or not self.kafka:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        logger.info("Starting Launchpad service...")

        def signal_handler(signum: int, frame) -> None:
            if self._shutdown_requested:
                logger.info(f"Received signal {signum} during shutdown, forcing exit...")
                os._exit(1)

            logger.info(f"Received signal {signum}, initiating shutdown...")
            self._shutdown_requested = True
            if self.kafka:
                self.kafka.stop()

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Start HTTP server in background thread
        self._server_thread = threading.Thread(
            target=self._run_http_server_thread,
            name="launchpad-http-server",
            daemon=True,
        )
        self._server_thread.start()

        logger.info("Launchpad service started successfully")

        try:
            # Run Kafka consumer in main thread (blocking)
            self.kafka.run()
        finally:
            logger.info("Cleaning up service resources...")
            self._shutdown_server()
            logger.info("Service cleanup completed")

    def is_healthy(self) -> bool:
        """Get overall service health status."""
        is_server_healthy = self.server.is_healthy()
        is_kafka_healthy = self.kafka.is_healthy()
        return is_server_healthy and is_kafka_healthy

    def _run_http_server_thread(self) -> None:
        self._server_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._server_loop)

        try:
            self._server_loop.run_until_complete(self.server.start())
            self._server_loop.run_forever()
        finally:
            self._server_loop.close()

    def _shutdown_server(self) -> None:
        if self._server_loop and self.server:
            future = asyncio.run_coroutine_threadsafe(self.server.stop(), self._server_loop)
            try:
                future.result(timeout=10)
            except Exception:
                logger.warning("Error during server shutdown", exc_info=True)

            self._server_loop.call_soon_threadsafe(self._server_loop.stop)

        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=10)


@dataclass
class ServiceConfig:
    """Service configuration data."""

    sentry_base_url: str
    projects_to_skip: list[str]
    objectstore_url: str | None


def get_service_config() -> ServiceConfig:
    """Get service configuration from environment."""
    sentry_base_url = os.getenv("SENTRY_BASE_URL")
    projects_to_skip_str = os.getenv("PROJECT_IDS_TO_SKIP")
    projects_to_skip = projects_to_skip_str.split(",") if projects_to_skip_str else []
    objectstore_url = os.getenv("OBJECTSTORE_URL")

    if sentry_base_url is None:
        sentry_base_url = "http://getsentry.default"

    return ServiceConfig(
        sentry_base_url=sentry_base_url,
        projects_to_skip=projects_to_skip,
        objectstore_url=objectstore_url,
    )


def run_service() -> None:
    """Run the Launchpad service."""
    statsd = get_statsd()
    service = LaunchpadService(statsd)
    service.setup()
    service.start()
