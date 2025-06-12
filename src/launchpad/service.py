"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any, Dict, Union

from .kafka import KafkaConsumer, LaunchpadMessage, get_kafka_config
from .server import LaunchpadServer, get_server_config

logger = logging.getLogger(__name__)


class LaunchpadService:
    """Main service that orchestrates HTTP server and Kafka consumer."""

    def __init__(self) -> None:
        self.server: LaunchpadServer | None = None
        self.kafka_consumer: KafkaConsumer | None = None
        self._shutdown_event = asyncio.Event()
        self._tasks: list[Union[asyncio.Task[Any], asyncio.Future[Any]]] = []
        self._kafka_task: asyncio.Future[Any] | None = None

    async def setup(self) -> None:
        """Set up the service components."""
        # Setup HTTP server
        server_config = get_server_config()
        self.server = LaunchpadServer(host=server_config["host"], port=server_config["port"])

        # Setup Kafka consumer
        kafka_config = get_kafka_config()
        self.kafka_consumer = KafkaConsumer(
            topics=kafka_config["topics"],
            group_id=kafka_config["group_id"],
            bootstrap_servers=kafka_config["bootstrap_servers"],
            message_handler=self.handle_kafka_message,
        )

        logger.info("Service components initialized")

    def handle_kafka_message(self, message: LaunchpadMessage) -> None:
        """Handle incoming Kafka messages (synchronous wrapper)."""
        try:
            logger.info(f"Received message from topic {message.topic}: {message.value!r}")

            # Parse message payload
            payload = message.get_json_payload()
            if not payload:
                logger.error("Failed to parse message payload")
                return

            # TODO: Route message to appropriate handler based on message type
            message_type = payload.get("type", "unknown")

            # TODO: !! ensure we utilize proper parallelism.
            # Right now, each analysis job will block the entire Kafka consumer until it completes
            if message_type == "analyze_ios":
                self._handle_ios_analysis_sync(payload)
            elif message_type == "analyze_android":
                self._handle_android_analysis_sync(payload)
            else:
                logger.warning(f"Unknown message type: {message_type}")

        except Exception as e:
            logger.error(f"Error handling Kafka message: {e}", exc_info=True)

    def _handle_ios_analysis_sync(self, payload: Dict[str, Any]) -> None:
        """Handle iOS analysis requests (synchronous)."""
        logger.info(f"Processing iOS analysis request: {payload}")
        # TODO: Integrate with app_size_analyzer for actual analysis
        # For now, just log the request
        logger.info("iOS analysis completed (stub)")

    def _handle_android_analysis_sync(self, payload: Dict[str, Any]) -> None:
        """Handle Android analysis requests (synchronous)."""
        logger.info(f"Processing Android analysis request: {payload}")
        # TODO: Implement Android analysis
        logger.info("Android analysis completed (stub)")

    async def start(self) -> None:
        """Start all service components."""
        if not self.server or not self.kafka_consumer:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        logger.info("Starting Launchpad service...")

        # Set up signal handlers for graceful shutdown first
        self._setup_signal_handlers()

        # Start Kafka consumer in a background thread (like Snuba)
        loop = asyncio.get_event_loop()
        self._kafka_task = loop.run_in_executor(None, self.kafka_consumer.run)
        # Just keep the Future in the tasks list - asyncio.gather can handle it
        self._tasks.append(self._kafka_task)

        # Start HTTP server as a background task
        server_task = asyncio.create_task(self.server.start())
        self._tasks.append(server_task)

        logger.info("Launchpad service started successfully")

        # Wait for shutdown signal
        await self._shutdown_event.wait()

        # Cleanup
        await self._cleanup()

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""

        def signal_handler(signum: int, frame: Any) -> None:
            if self._shutdown_event.is_set():
                logger.info(f"Received signal {signum} during shutdown, ignoring...")
                return

            logger.info(f"Received signal {signum}, initiating shutdown...")

            # Signal Kafka consumer shutdown immediately (like Snuba)
            if self.kafka_consumer:
                try:
                    logger.info("Signal handler: signaling Kafka consumer shutdown")
                    self.kafka_consumer.shutdown()
                except Exception as e:
                    logger.warning(f"Error in signal handler stopping Kafka: {e}")

            # Cancel the kafka task directly to interrupt the executor thread
            if self._kafka_task and not self._kafka_task.done():
                try:
                    logger.info("Signal handler: cancelling Kafka task")
                    self._kafka_task.cancel()
                except Exception as e:
                    logger.warning(f"Error cancelling Kafka task: {e}")

            # Set the shutdown event to start async cleanup
            self._shutdown_event.set()

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

    async def _cleanup(self) -> None:
        """Clean up service resources."""
        logger.info("Cleaning up service resources...")

        # Stop Kafka consumer first (signal shutdown)
        if self.kafka_consumer:
            try:
                logger.info("Signaling Kafka consumer to shutdown")
                self.kafka_consumer.shutdown()
                logger.info("Kafka consumer shutdown signal sent")
            except Exception as e:
                logger.warning(f"Error stopping Kafka consumer: {e}")

        # Stop HTTP server
        if self.server:
            try:
                self.server.shutdown()
                logger.info("HTTP server stopped")
            except Exception as e:
                logger.warning(f"Error shutting down server: {e}")

        # Wait for all tasks to complete or timeout
        if self._tasks:
            try:
                logger.info("Waiting for tasks to complete...")
                await asyncio.wait_for(asyncio.gather(*self._tasks, return_exceptions=True), timeout=5.0)
                logger.info("All tasks completed")
            except asyncio.TimeoutError:
                logger.warning("Some tasks did not complete within timeout, cancelling remaining tasks")
                # Cancel remaining tasks if they didn't complete
                for task in self._tasks:
                    if not task.done():
                        logger.info(f"Cancelling task: {task}")
                        task.cancel()

                # Give cancelled tasks a moment to clean up
                try:
                    await asyncio.wait_for(asyncio.gather(*self._tasks, return_exceptions=True), timeout=2.0)
                except asyncio.TimeoutError:
                    logger.warning("Some tasks did not respond to cancellation")

        logger.info("Service cleanup completed")

    async def health_check(self) -> Dict[str, Any]:
        """Get overall service health status."""
        health_status: Dict[str, Any] = {"service": "launchpad", "status": "ok", "components": {}}

        # Check Kafka health
        if self.kafka_consumer:
            kafka_health = await self.kafka_consumer.health_check()
            health_status["components"]["kafka"] = kafka_health

        # Check server health
        health_status["components"]["server"] = {"status": "ok" if self.server else "not_initialized"}

        return health_status


async def run_service() -> None:
    """Run the Launchpad service."""
    service = LaunchpadService()
    await service.setup()
    await service.start()
