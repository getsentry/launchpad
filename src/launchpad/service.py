"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any, Dict

from dotenv import load_dotenv

from .kafka import KafkaConsumer, LaunchpadMessage, get_kafka_config
from .server import LaunchpadServer, get_server_config

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


class LaunchpadWebService:
    """Web-only service that runs just the HTTP server."""

    def __init__(self) -> None:
        self.server: LaunchpadServer | None = None
        self._shutdown_initiated = False

    async def setup(self) -> None:
        """Set up the web service components."""
        server_config = get_server_config()
        self.server = LaunchpadServer(host=server_config["host"], port=server_config["port"])
        logger.info("Web service components initialized")

    async def start(self) -> None:
        """Start the web service."""
        if not self.server:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        logger.info("Starting Launchpad web service...")

        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()

        # Start HTTP server (this will block until shutdown)
        await self.server.start()

        logger.info("Web service shutdown completed")

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""

        def signal_handler() -> None:
            if self._shutdown_initiated:
                logger.info("Received signal during shutdown, ignoring...")
                return

            logger.info("Received shutdown signal, initiating shutdown...")
            self._shutdown_initiated = True

            if self.server:
                self.server.shutdown()

        # Use asyncio's signal handling which properly integrates with the event loop
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)

    async def health_check(self) -> Dict[str, Any]:
        """Get web service health status."""
        return {
            "service": "launchpad-web",
            "status": "ok",
            "components": {"server": {"status": "ok" if self.server else "not_initialized"}},
        }


class LaunchpadConsumerService:
    """Consumer-only service that runs just the Kafka consumer."""

    def __init__(self) -> None:
        self.kafka_consumer: KafkaConsumer | None = None
        self._shutdown_event = asyncio.Event()
        self._kafka_task: asyncio.Future[Any] | None = None
        self._shutdown_initiated = False

    async def setup(self) -> None:
        """Set up the consumer service components."""
        kafka_config = get_kafka_config()
        self.kafka_consumer = KafkaConsumer(
            topics=kafka_config["topics"],
            group_id=kafka_config["group_id"],
            bootstrap_servers=kafka_config["bootstrap_servers"],
            message_handler=self.handle_kafka_message,
        )
        logger.info("Consumer service components initialized")

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
            if message_type == "analyze_apple":
                self._handle_apple_analysis_sync(payload)
            elif message_type == "analyze_android":
                self._handle_android_analysis_sync(payload)
            else:
                logger.warning(f"Unknown message type: {message_type}")

        except Exception as e:
            logger.error(f"Error handling Kafka message: {e}", exc_info=True)

    def _handle_apple_analysis_sync(self, payload: Dict[str, Any]) -> None:
        """Handle Apple analysis requests (synchronous)."""
        logger.info(f"Processing Apple analysis request: {payload}")
        # TODO: Integrate with app_size_analyzer for actual analysis
        # For now, just log the request
        logger.info("Apple app analysis completed (stub)")

    def _handle_android_analysis_sync(self, payload: Dict[str, Any]) -> None:
        """Handle Android analysis requests (synchronous)."""
        logger.info(f"Processing Android analysis request: {payload}")
        # TODO: Implement Android analysis
        logger.info("Android analysis completed (stub)")

    async def start(self) -> None:
        """Start the consumer service."""
        if not self.kafka_consumer:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        logger.info("Starting Launchpad consumer service...")

        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()

        # Start Kafka consumer in a background thread
        loop = asyncio.get_event_loop()
        self._kafka_task = loop.run_in_executor(None, self.kafka_consumer.run)

        logger.info("Launchpad consumer service started successfully")

        # Wait for shutdown signal
        await self._shutdown_event.wait()

        # Cleanup
        await self._cleanup()

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""

        def signal_handler() -> None:
            if self._shutdown_event.is_set():
                logger.info("Received signal during shutdown, ignoring...")
                return

            logger.info("Received shutdown signal, initiating shutdown...")
            self._shutdown_initiated = True

            # Signal Kafka consumer shutdown immediately
            if self.kafka_consumer:
                logger.info("Signaling Kafka consumer shutdown")
                self.kafka_consumer.shutdown()

            # Cancel the kafka task directly to interrupt the executor thread
            if self._kafka_task and not self._kafka_task.done():
                self._kafka_task.cancel()

            # Set the shutdown event to start async cleanup
            self._shutdown_event.set()

        # Use asyncio's signal handling which properly integrates with the event loop
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)

    async def _cleanup(self) -> None:
        """Clean up consumer resources."""
        logger.info("Cleaning up consumer resources...")

        # Only call shutdown if it wasn't already called by signal handler
        if self.kafka_consumer and not self._shutdown_initiated:
            logger.info("Signaling Kafka consumer to shutdown")
            self.kafka_consumer.shutdown()

        # Wait for Kafka task to complete
        if self._kafka_task:
            try:
                await asyncio.wait_for(self._kafka_task, timeout=5.0)
                logger.info("Kafka task completed")
            except asyncio.CancelledError:
                logger.info("Kafka task was cancelled (expected during shutdown)")
            except asyncio.TimeoutError:
                logger.warning("Kafka task did not complete within timeout, cancelling...")
                self._kafka_task.cancel()
                try:
                    await asyncio.wait_for(self._kafka_task, timeout=2.0)
                    logger.info("Kafka task completed after cancellation")
                except asyncio.CancelledError:
                    logger.info("Kafka task was cancelled (expected)")
                except asyncio.TimeoutError:
                    logger.warning("Kafka task did not respond to cancellation")

        logger.info("Consumer cleanup completed")

    async def health_check(self) -> Dict[str, Any]:
        """Get consumer service health status."""
        health_status: Dict[str, Any] = {"service": "launchpad-consumer", "status": "ok", "components": {}}

        # Check Kafka health
        if self.kafka_consumer:
            kafka_health = await self.kafka_consumer.health_check()
            health_status["components"]["kafka"] = kafka_health

        return health_status


# Backwards compatibility functions
async def run_web_service() -> None:
    """Run only the web service."""
    service = LaunchpadWebService()
    await service.setup()
    await service.start()


async def run_consumer_service() -> None:
    """Run only the consumer service."""
    service = LaunchpadConsumerService()
    await service.setup()
    await service.start()


async def run_service() -> None:
    """Run both web and consumer services together (for development)."""
    logger.info("Starting combined Launchpad service...")

    # Create and setup both services
    web_service = LaunchpadWebService()
    consumer_service = LaunchpadConsumerService()

    await web_service.setup()
    await consumer_service.setup()

    logger.info("Combined service components initialized")

    # Start both services as background tasks
    web_task = asyncio.create_task(web_service.start())
    consumer_task = asyncio.create_task(consumer_service.start())

    logger.info("Combined Launchpad service started successfully")

    # Wait for any task to complete (which means shutdown was triggered)
    try:
        await asyncio.wait([web_task, consumer_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        # Cancel any remaining tasks
        for task in [web_task, consumer_task]:
            if not task.done():
                task.cancel()

        # Wait for cancellation to complete
        await asyncio.gather(web_task, consumer_task, return_exceptions=True)
        logger.info("Combined service shutdown completed")
