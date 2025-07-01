"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import json
import os
import signal
<<<<<<< HEAD

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Union
=======
import tempfile
import time

from pathlib import Path
from typing import Any, Dict
>>>>>>> 7ac852b (hodl)

from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import DogStatsd, get_statsd

<<<<<<< HEAD
from .kafka import KafkaConsumer, LaunchpadMessage, get_kafka_config
=======
from .kafka import create_kafka_consumer
from .sentry_client import SentryClient
>>>>>>> 7ac852b (hodl)
from .server import LaunchpadServer, get_server_config
from .size.runner import do_size

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
        self._statsd: DogStatsd | None = None

    async def setup(self) -> None:
        """Set up the service components."""
        # Store reference to the event loop for use in message handlers
        self._loop = asyncio.get_running_loop()

        service_config = get_service_config()
        self._statsd = get_statsd(host=service_config["statsd_host"], port=service_config["statsd_port"])

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

    def _download_and_analyze_artifact(self, org_id: str, project_id: str, artifact_id: str) -> Dict[str, Any]:
        """Download artifact and run size analysis."""
        if not self._sentry_client:
            raise RuntimeError("Sentry client not initialized")

        # Download the artifact
        logger.info(f"Downloading artifact {artifact_id} from Sentry...")
        download_result = self._sentry_client.download_artifact(
            org=org_id,
            project=project_id,
            artifact_id=artifact_id,
        )

        if "error" in download_result:
            raise RuntimeError(f"Failed to download artifact: {download_result['error']}")

        file_content = download_result.get("file_content")
        if not file_content:
            raise RuntimeError("Downloaded artifact has no content")

        file_size = download_result.get("file_size_bytes", len(file_content))
        logger.info(f"Downloaded artifact: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)")

        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_file:
            tmp_file.write(file_content)
            tmp_path = Path(tmp_file.name)

        try:
            logger.info(f"Running size analysis on {tmp_path}")

            # Run the size analysis
            results = do_size(tmp_path)

            # Log summary of results
            logger.info(
                f"Analysis complete: "
                f"platform={results.platform}, "
                f"total_size={results.total_size}, "
                f"duration={results.analysis_duration:.2f}s"
            )

            # Convert results to dict for easier handling
            results_dict = results.to_dict()

            # Print detailed results for debugging
            logger.info(f"Full analysis results:\n{json.dumps(results_dict, indent=2)}")

            return {
                "success": True,
                "results": results_dict,
                "artifact_id": artifact_id,
                "file_size": file_size,
            }

        finally:
            # Clean up temporary file
            if tmp_path.exists():
                tmp_path.unlink()
                logger.debug(f"Cleaned up temporary file: {tmp_path}")

    def handle_kafka_message(self, payload: PreprodArtifactEvents) -> None:
        """
        Handle incoming Kafka messages.
        """
        artifact_id = payload["artifact_id"]
        project_id = payload["project_id"]
        organization_id = payload["organization_id"]

        try:
            logger.info(
                f"Starting analysis for artifact: {artifact_id} (project: {project_id}, org: {organization_id})"
            )

            # Run the actual analysis in thread pool to avoid blocking event loop
            if not self._loop:
                raise RuntimeError("Event loop not initialized")
            await self._loop.run_in_executor(self._task_executor, self._do_analysis, payload)

            logger.info(f"Analysis completed for artifact: {artifact_id}")

        except Exception as e:
            logger.error(f"Analysis failed for artifact {artifact_id}: {e}", exc_info=True)

    def _do_analysis(self, payload: PreprodArtifactEvents) -> None:
        """Actual analysis work (runs in thread pool) - platform determined by artifact."""
        artifact_id = payload["artifact_id"]  # Guaranteed by schema
        project_id = payload["project_id"]  # Guaranteed by schema
        organization_id = payload["organization_id"]  # Guaranteed by schema

        self._statsd.increment("launchpad.do_analysis")

        logger.info(f"Processing analysis request for artifact {artifact_id}")
        logger.info(f"Project ID: {project_id}, Organization ID: {organization_id}")

        # TODO: Implement actual analysis logic
        # This will need to:
        # 1. Fetch the artifact using artifact_id from storage/API
        # 2. Determine platform by examining the artifact
        # 3. Run appropriate analyzer (iOS/Android)
        # 4. Store results

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
                await asyncio.wait_for(
                    asyncio.gather(*self._background_tasks, return_exceptions=True),
                    timeout=30.0,
                )
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
                    await asyncio.wait_for(
                        asyncio.gather(*self._tasks, return_exceptions=True),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning("Some tasks did not respond to cancellation")

        # Shut down the thread pool executor
        logger.info("Shutting down thread pool executor...")
        self._task_executor.shutdown(wait=True, cancel_futures=True)
        logger.info("Thread pool executor shut down")

        logger.info("Service cleanup completed")

    async def health_check(self) -> Dict[str, Any]:
        """Get overall service health status."""
        health_status: Dict[str, Any] = {
            "service": "launchpad",
            "status": "ok",
            "components": {},
        }

        # Check Kafka health
        if self.kafka_consumer:
            kafka_health = await self.kafka_consumer.health_check()
            health_status["components"]["kafka"] = kafka_health

        # Check server health
        health_status["components"]["server"] = {"status": "ok" if self.server else "not_initialized"}

        return health_status


def get_service_config() -> Dict[str, Any]:
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
