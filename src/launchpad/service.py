"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import os
import signal
import time

from typing import Any, Dict

from arroyo.backends.kafka import KafkaPayload
from arroyo.processing.processor import StreamProcessor
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import DogStatsd, get_statsd

from .kafka import create_kafka_consumer
from .server import HealthCheckResponse, LaunchpadServer, get_server_config

logger = get_logger(__name__)

# Health check threshold - consider unhealthy if file not touched in 60 seconds
HEALTHCHECK_MAX_AGE_SECONDS = 60.0


class LaunchpadService:
    """Main service that orchestrates HTTP server and Kafka consumer."""

    def __init__(self) -> None:
        self.server: LaunchpadServer | None = None
        self.kafka_processor: StreamProcessor[KafkaPayload] | None = None
        self._shutdown_event = asyncio.Event()
        self._kafka_task: asyncio.Future[Any] | None = None
        self._statsd: DogStatsd | None = None
        self._healthcheck_file: str | None = None

    async def setup(self) -> None:
        """Set up the service components."""
        service_config = get_service_config()
        self._statsd = get_statsd(host=service_config["statsd_host"], port=service_config["statsd_port"])

        # Setup HTTP server with health check callback
        server_config = get_server_config()
        self.server = LaunchpadServer(
            host=server_config["host"],
            port=server_config["port"],
            health_check_callback=self.health_check,
        )

        # Setup healthcheck file if not configured
        self._healthcheck_file = os.getenv("KAFKA_HEALTHCHECK_FILE")
        if not self._healthcheck_file:
            # Create a default healthcheck file in tmp
            self._healthcheck_file = f"/tmp/launchpad-kafka-health-{os.getpid()}"
            os.environ["KAFKA_HEALTHCHECK_FILE"] = self._healthcheck_file
            logger.info(f"Using healthcheck file: {self._healthcheck_file}")

        # Create Kafka consumer with message handler
        self.kafka_processor = create_kafka_consumer(message_handler=self.handle_kafka_message)

        logger.info("Service components initialized")

    def handle_kafka_message(self, payload: PreprodArtifactEvents) -> None:
        """
        Handle incoming Kafka messages.
        """
        artifact_id = payload["artifact_id"]
        project_id = payload["project_id"]
        organization_id = payload["organization_id"]

        try:
            logger.info(f"Processing artifact: {artifact_id} (project: {project_id}, org: {organization_id})")

            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.started")

            # TODO: Implement actual analysis logic
            # This will need to:
            # 1. Fetch the artifact using artifact_id from storage/API
            # 2. Determine platform by examining the artifact
            # 3. Run appropriate analyzer (iOS/Android)
            # 4. Store results

            # For now, just log
            logger.info(f"Analysis completed for artifact {artifact_id} (stub)")

            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.completed")

        except Exception as e:
            logger.error(f"Analysis failed for artifact {artifact_id}: {e}", exc_info=True)
            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.failed")
            # Re-raise to let Arroyo handle the error (can be configured for DLQ)
            raise

    async def start(self) -> None:
        """Start all service components."""
        if not self.server or not self.kafka_processor:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        logger.info("Starting Launchpad service...")

        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()

        # Start Kafka processor in a background thread
        loop = asyncio.get_event_loop()
        self._kafka_task = loop.run_in_executor(None, self.kafka_processor.run)

        # Start HTTP server as a background task
        server_task = asyncio.create_task(self.server.start())

        logger.info("Launchpad service started successfully")

        try:
            # Wait for shutdown signal
            await self._shutdown_event.wait()
        finally:
            # Cleanup
            await self._cleanup(server_task)

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""

        def signal_handler(signum: int, frame: Any) -> None:
            if self._shutdown_event.is_set():
                logger.info(f"Received signal {signum} during shutdown, ignoring...")
                return

            logger.info(f"Received signal {signum}, initiating shutdown...")

            # Signal Kafka processor shutdown
            if self.kafka_processor:
                try:
                    self.kafka_processor.signal_shutdown()
                except Exception as e:
                    logger.warning(f"Error stopping Kafka processor: {e}")

            # Set the shutdown event
            self._shutdown_event.set()

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

    async def _cleanup(self, server_task: asyncio.Task[Any]) -> None:
        """Clean up service resources."""
        logger.info("Cleaning up service resources...")

        # Stop HTTP server
        if self.server:
            try:
                self.server.shutdown()
                await asyncio.wait_for(server_task, timeout=5.0)
                logger.info("HTTP server stopped")
            except asyncio.TimeoutError:
                logger.warning("HTTP server did not stop within timeout")
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    pass
            except Exception as e:
                logger.warning(f"Error shutting down server: {e}")

        # Wait for Kafka processor to stop
        if self._kafka_task:
            try:
                logger.info("Waiting for Kafka processor to stop...")
                await asyncio.wait_for(self._kafka_task, timeout=10.0)
                logger.info("Kafka processor stopped")
            except asyncio.TimeoutError:
                logger.warning("Kafka processor did not stop within timeout")
                self._kafka_task.cancel()
            except Exception as e:
                logger.warning(f"Error waiting for Kafka processor: {e}")

        # Clean up healthcheck file
        if self._healthcheck_file and os.path.exists(self._healthcheck_file):
            try:
                os.remove(self._healthcheck_file)
                logger.info(f"Removed healthcheck file: {self._healthcheck_file}")
            except Exception as e:
                logger.warning(f"Failed to remove healthcheck file: {e}")

        logger.info("Service cleanup completed")

    async def health_check(self) -> HealthCheckResponse:
        """Get overall service health status."""
        health_status: HealthCheckResponse = {
            "service": "launchpad",
            "status": "ok",
            "components": {},
        }

        # Check Kafka health via healthcheck file
        kafka_health: Dict[str, Any] = {"status": "unknown"}
        if self._healthcheck_file:
            try:
                if os.path.exists(self._healthcheck_file):
                    # Check file modification time
                    mtime = os.path.getmtime(self._healthcheck_file)
                    age = time.time() - mtime

                    if age <= HEALTHCHECK_MAX_AGE_SECONDS:
                        kafka_health = {
                            "status": "healthy",
                            "last_heartbeat_age_seconds": round(age, 2),
                        }
                    else:
                        kafka_health = {
                            "status": "unhealthy",
                            "last_heartbeat_age_seconds": round(age, 2),
                            "reason": f"No heartbeat for {round(age, 2)} seconds",
                        }
                        health_status["status"] = "degraded"
                else:
                    kafka_health = {
                        "status": "unhealthy",
                        "reason": "Healthcheck file does not exist",
                    }
                    health_status["status"] = "degraded"
            except Exception as e:
                kafka_health = {"status": "error", "reason": str(e)}
                health_status["status"] = "degraded"
        else:
            kafka_health = {
                "status": "unknown",
                "reason": "No healthcheck file configured",
            }

        health_status["components"]["kafka"] = kafka_health

        # Check server health
        health_status["components"]["server"] = {"status": "ok" if self.server else "not_initialized"}

        return health_status


def get_service_config() -> Dict[str, Any]:
    """Get service configuration from environment."""
    statsd_host = os.getenv("STATSD_HOST", "127.0.0.1")
    statsd_port_str = os.getenv("STATSD_PORT", "8125")

    try:
        statsd_port = int(statsd_port_str)
    except ValueError:
        raise ValueError(f"STATSD_PORT must be a valid integer, got: {statsd_port_str}")

    return {
        "statsd_host": statsd_host,
        "statsd_port": statsd_port,
    }


async def run_service() -> None:
    """Run the Launchpad service."""
    service = LaunchpadService()
    await service.setup()
    await service.start()
