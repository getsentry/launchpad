"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import signal
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Union

from launchpad.utils.logging import get_logger

from .kafka import KafkaConsumer, LaunchpadMessage, get_kafka_config
from .server import LaunchpadServer, get_server_config

logger = get_logger(__name__)


class LaunchpadService:
    """Main service that orchestrates HTTP server and Kafka consumer."""

    def __init__(self) -> None:
        self.server: LaunchpadServer | None = None
        self.kafka_consumer: KafkaConsumer | None = None
        self._shutdown_event = asyncio.Event()
        self._tasks: list[Union[asyncio.Task[Any], asyncio.Future[Any]]] = []
        self._kafka_task: asyncio.Future[Any] | None = None
        self._task_executor = ThreadPoolExecutor(max_workers=4)  # Adjust based on resources
        self._background_tasks: set[asyncio.Task[Any]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    async def setup(self) -> None:
        """Set up the service components."""
        # Store reference to the event loop for use in message handlers
        self._loop = asyncio.get_running_loop()

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
        """Handle incoming Kafka messages - immediately queue for background processing."""
        try:
            logger.info(f"Received message from topic {message.topic}")

            # Parse message payload
            payload = message.get_json_payload()
            if not payload:
                logger.error("Failed to parse message payload")
                return

            # Route message to appropriate handler based on message type
            message_type = payload.get("type", "unknown")

            # Queue task immediately - don't block the consumer
            # Use call_soon_threadsafe since we're being called from the Kafka consumer thread
            if message_type == "analyze_artifact":
                if self._loop:
                    self._loop.call_soon_threadsafe(self._queue_analysis, payload)
            else:
                logger.warning(f"Unknown message type: {message_type}")

        except Exception as e:
            logger.error(f"Error handling Kafka message: {e}", exc_info=True)

    def _queue_analysis(self, payload: Dict[str, Any]) -> None:
        """Queue analysis for background processing."""
        try:
            if not self._loop:
                raise RuntimeError("Event loop not initialized")

            # Create background task using stored loop reference
            task = self._loop.create_task(self._handle_analysis_async(payload))
            self._background_tasks.add(task)

            # Clean up completed tasks with error logging (platform will be determined later)
            def task_done_callback(completed_task: asyncio.Task[Any]) -> None:
                self._background_tasks.discard(completed_task)
                if completed_task.exception():
                    logger.error(f"Analysis task failed: {completed_task.exception()}")

            task.add_done_callback(task_done_callback)

            artifact_id = payload.get("artifact_id", payload.get("id", "unknown"))
            logger.info(f"Queued analysis task for artifact: {artifact_id}")

        except Exception as e:
            logger.error(f"Failed to queue analysis: {e}", exc_info=True)

    async def _handle_analysis_async(self, payload: Dict[str, Any]) -> None:
        """Handle analysis in background thread."""
        artifact_id = payload.get("artifact_id", payload.get("id", "unknown"))

        try:
            logger.info(f"Starting analysis for artifact: {artifact_id}")

            # Run the actual analysis in thread pool to avoid blocking event loop
            if not self._loop:
                raise RuntimeError("Event loop not initialized")
            await self._loop.run_in_executor(self._task_executor, self._do_analysis, payload)

            logger.info(f"Analysis completed for artifact: {artifact_id}")

        except Exception as e:
            logger.error(f"Analysis failed for artifact {artifact_id}: {e}", exc_info=True)

    def _do_analysis(self, payload: Dict[str, Any]) -> None:
        """Actual analysis work (runs in thread pool) - platform determined by artifact."""
        artifact_id = payload.get("artifact_id", payload.get("id", "unknown"))
        artifact_path = payload.get("artifact_path")

        logger.info(f"Processing analysis request for artifact {artifact_id}")
        logger.info(f"Artifact path: {artifact_path}")

        # TODO: Implement actual analysis logic
        # This will determine platform by examining the artifact and run appropriate analyzer

        logger.info(f"Analysis completed for artifact {artifact_id} (stub)")

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

        # Wait for background analysis tasks to complete or timeout
        if self._background_tasks:
            logger.info(f"Waiting for {len(self._background_tasks)} background tasks to complete...")
            try:
                await asyncio.wait_for(asyncio.gather(*self._background_tasks, return_exceptions=True), timeout=30.0)
                logger.info("All background tasks completed")
            except asyncio.TimeoutError:
                logger.warning("Background tasks did not complete within timeout, cancelling...")
                for task in self._background_tasks:
                    task.cancel()
                # Wait a bit for cancellation to complete
                await asyncio.gather(*self._background_tasks, return_exceptions=True)

        # Wait for all other tasks to complete or timeout
        if self._tasks:
            try:
                logger.info("Waiting for service tasks to complete...")
                await asyncio.wait_for(asyncio.gather(*self._tasks, return_exceptions=True), timeout=5.0)
                logger.info("All service tasks completed")
            except asyncio.TimeoutError:
                logger.warning("Some service tasks did not complete within timeout, cancelling remaining tasks")
                # Cancel remaining tasks if they didn't complete
                for task in self._tasks:  # type: ignore[assignment]
                    if not task.done():
                        logger.info(f"Cancelling task: {task}")
                        task.cancel()

                # Give cancelled tasks a moment to clean up
                try:
                    await asyncio.wait_for(asyncio.gather(*self._tasks, return_exceptions=True), timeout=2.0)
                except asyncio.TimeoutError:
                    logger.warning("Some tasks did not respond to cancellation")

        # Shut down the thread pool executor
        logger.info("Shutting down thread pool executor...")
        self._task_executor.shutdown(wait=True, cancel_futures=True)
        logger.info("Thread pool executor shut down")

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
