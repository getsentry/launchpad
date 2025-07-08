"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import tempfile
import time
import re
import zipfile

from typing import Any, Dict, cast
from pathlib import Path

from arroyo.backends.kafka import KafkaPayload
from arroyo.processing.processor import StreamProcessor
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.sentry_client import SentryClient
from launchpad.size.runner import do_size, do_preprocess
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.android import AndroidAppInfo
from launchpad.size.models.apple import AppleAppInfo
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
        self._service_config: Dict[str, Any] | None = None

    async def setup(self) -> None:
        """Set up the service components."""
        self._service_config = get_service_config()
        self._statsd = get_statsd(
            host=self._service_config["statsd_host"],
            port=self._service_config["statsd_port"],
        )

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
        self.kafka_processor = create_kafka_consumer(
            message_handler=self.handle_kafka_message
        )

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
        self.kafka_processor = create_kafka_consumer(
            message_handler=self.handle_kafka_message
        )

        logger.info("Service components initialized")

    def process_artifact_analysis(
        self, artifact_id: str, project_id: str, organization_id: str
    ) -> None:
        """
        Download artifact and perform size analysis.
        """
        if not self._service_config:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        sentry_base_url = self._service_config["sentry_base_url"]
        sentry_client = SentryClient(base_url=sentry_base_url)

        # Download the artifact
        logger.info(f"Downloading artifact {artifact_id}...")
        download_result = sentry_client.download_artifact(
            org=organization_id, project=project_id, artifact_id=artifact_id
        )

        if "error" in download_result:
            # Use structured error categorization
            error_category, error_description = _categorize_http_error(download_result)
            raise RuntimeError(
                f"Failed to download artifact ({error_category}): {error_description}"
            )

        if not download_result.get("success"):
            raise RuntimeError(f"Download was not successful: {download_result}")

        file_content = download_result["file_content"]
        file_size = download_result["file_size_bytes"]

        logger.info(
            f"Downloaded artifact {artifact_id}: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)"
        )

        # Save to temporary file
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tf:
                tf.write(file_content)
                temp_file = tf.name

            logger.info(f"Saved artifact to temporary file: {temp_file}")

            # Create artifact instance to determine type before preprocessing
            from launchpad.artifacts.artifact_factory import ArtifactFactory

            artifact = ArtifactFactory.from_path(Path(temp_file))

            # Run preprocessing first
            logger.info(f"Running preprocessing on {temp_file}...")
            app_info = do_preprocess(Path(temp_file))
            logger.info(f"Preprocessing completed for artifact {artifact_id}")

            # Prepare update data based on platform
            update_data: Dict[str, Any] = {}

            if isinstance(app_info, AppleAppInfo):
                # Apple/iOS artifact (XCARCHIVE)
                update_data = {
                    "build_version": app_info.version,
                    "build_number": (
                        int(app_info.build)
                        if str(app_info.build).isdigit()
                        else app_info.build
                    ),  # perhaps we shouldnt even include it if it isnt an int
                    "artifact_type": 0,  # 0 = XCARCHIVE
                    "apple_app_info": {
                        "is_simulator": app_info.is_simulator,
                        "codesigning_type": app_info.codesigning_type,
                        "profile_name": app_info.profile_name,
                        "is_code_signature_valid": app_info.is_code_signature_valid,
                        "code_signature_errors": app_info.code_signature_errors,
                    },
                }
            elif isinstance(app_info, AndroidAppInfo):
                # Android artifact - need to determine if AAB or APK
                # Check the actual artifact type from the file
                from launchpad.artifacts.android.aab import AAB
                from launchpad.artifacts.android.zipped_aab import ZippedAAB

                if isinstance(artifact, (AAB, ZippedAAB)):
                    artifact_type = 1  # 1 = AAB
                else:
                    artifact_type = 2  # 2 = APK

                update_data = {
                    "build_version": app_info.version,
                    "build_number": (
                        int(app_info.build) if app_info.build.isdigit() else None
                    ),
                    "artifact_type": artifact_type,
                }

            # Send update to Sentry
            logger.info(
                f"Sending preprocessed info to Sentry for artifact {artifact_id}..."
            )
            logger.info(
                f"!!!!$$$$$$Update data for artifact {artifact_id}: {update_data}"
            )
            update_result = sentry_client.update_artifact(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data=update_data,
            )

            if "error" in update_result:
                logger.error(
                    f"Failed to send preprocessed info: {update_result['error']}"
                )
                # Don't raise - preprocessing succeeded, just update failed
            else:
                logger.info(
                    f"Successfully sent preprocessed info for artifact {artifact_id}"
                )

            # Create analyzer with preprocessed info to avoid duplicate work
            analyzer: AndroidAnalyzer | AppleAppAnalyzer
            if isinstance(app_info, AndroidAppInfo):
                analyzer = AndroidAnalyzer()
                analyzer.app_info = app_info
            else:  # AppleAppInfo
                analyzer = AppleAppAnalyzer()
                analyzer.app_info = app_info

            # Run full analysis with the pre-configured analyzer
            logger.info(f"Running full analysis on {temp_file}...")
            results = do_size(Path(temp_file), analyzer=analyzer)

            logger.info(f"Size analysis completed for artifact {artifact_id}")

            # Write results to temporary file for upload
            analysis_file = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as af:
                    json.dump(results.to_dict(), af, indent=2)
                    analysis_file = af.name

                logger.info(
                    f"Analysis results written to temporary file: {analysis_file}"
                )

                # Upload the analysis file back to Sentry
                logger.info(f"Uploading analysis results for artifact {artifact_id}...")
                upload_result = sentry_client.upload_size_analysis_file(
                    org=organization_id,
                    project=project_id,
                    artifact_id=artifact_id,
                    file_path=analysis_file,
                )

                if "error" in upload_result:
                    logger.error(
                        f"Failed to upload analysis results: {upload_result['error']}"
                    )
                    # Don't raise - analysis succeeded, just upload failed
                else:
                    logger.info(
                        f"Successfully uploaded analysis results for artifact {artifact_id}"
                    )

            finally:
                # Clean up analysis file
                if analysis_file and os.path.exists(analysis_file):
                    try:
                        os.remove(analysis_file)
                        logger.debug(f"Cleaned up analysis file: {analysis_file}")
                    except Exception as e:
                        logger.warning(
                            f"Failed to clean up analysis file {analysis_file}: {e}"
                        )

        finally:
            # Clean up temporary file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                    logger.debug(f"Cleaned up temporary file: {temp_file}")
                except Exception as e:
                    logger.warning(
                        f"Failed to clean up temporary file {temp_file}: {e}"
                    )

    def handle_kafka_message(self, payload: PreprodArtifactEvents) -> None:
        """
        Handle incoming Kafka messages.
        """
        artifact_id = payload["artifact_id"]
        project_id = payload["project_id"]
        organization_id = payload["organization_id"]

        try:
            logger.info(
                f"Processing artifact: {artifact_id} (project: {project_id}, org: {organization_id})"
            )

            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.started")

            # Perform the actual artifact analysis
            self.process_artifact_analysis(artifact_id, project_id, organization_id)

            logger.info(f"Analysis completed for artifact {artifact_id}")

            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.completed")

        except RuntimeError as e:
            # Handle expected errors without crashing the consumer
            error_msg = str(e)

            # Use proper error categorization instead of string matching
            if "(not_found)" in error_msg:
                logger.warning(
                    f"Artifact not found: {artifact_id} (project: {project_id}, org: {organization_id}). "
                    "This may be a test message or the artifact may have been deleted."
                )
                if self._statsd:
                    self._statsd.increment("launchpad.artifact.processing.not_found")
            elif "(server_error)" in error_msg:
                logger.error(
                    f"Server error downloading artifact {artifact_id}: {e}. "
                    "This is likely a temporary issue with the Sentry API."
                )
                if self._statsd:
                    self._statsd.increment("launchpad.artifact.processing.server_error")
            elif "(client_error)" in error_msg:
                logger.error(
                    f"Client error downloading artifact {artifact_id}: {e}. "
                    "This may indicate a permissions issue or malformed request."
                )
                if self._statsd:
                    self._statsd.increment("launchpad.artifact.processing.client_error")
            else:
                logger.error(
                    f"Analysis failed for artifact {artifact_id}: {e}", exc_info=True
                )
                if self._statsd:
                    self._statsd.increment("launchpad.artifact.processing.failed")
            # Don't re-raise - let the consumer continue processing other messages
        except ValueError as e:
            # Handle artifact type validation errors gracefully
            error_msg = str(e)
            if "Input is not a supported artifact" in error_msg:
                logger.warning(
                    f"Unsupported artifact type for artifact {artifact_id} (project: {project_id}, org: {organization_id}): {e}. "
                    "This artifact format is not currently supported by the analyzer."
                )
                if self._statsd:
                    self._statsd.increment(
                        "launchpad.artifact.processing.unsupported_type"
                    )
            else:
                logger.error(
                    f"Validation error processing artifact {artifact_id}: {e}",
                    exc_info=True,
                )
                if self._statsd:
                    self._statsd.increment(
                        "launchpad.artifact.processing.validation_error"
                    )
            # Don't re-raise - let the consumer continue processing other messages
        except (OSError, IOError, FileNotFoundError, PermissionError) as e:
            # Handle file I/O errors gracefully
            logger.error(
                f"File I/O error processing artifact {artifact_id} (project: {project_id}, org: {organization_id}): {e}. "
                "This may indicate a corrupted artifact or file system issue."
            )
            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.io_error")
            # Don't re-raise - let the consumer continue processing other messages
        except zipfile.BadZipFile as e:
            # Handle corrupted zip files gracefully
            logger.error(
                f"Corrupted zip file for artifact {artifact_id} (project: {project_id}, org: {organization_id}): {e}. "
                "This artifact appears to be a corrupted or invalid zip file."
            )
            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.bad_zip")
            # Don't re-raise - let the consumer continue processing other messages
        except Exception as e:
            # Handle zip file corruption and other parsing errors gracefully
            error_msg = str(e)
            if any(
                keyword in error_msg.lower()
                for keyword in ["zip", "corrupt", "invalid", "bad magic"]
            ):
                logger.error(
                    f"Artifact corruption/parsing error for artifact {artifact_id} (project: {project_id}, org: {organization_id}): {e}. "
                    "This may indicate a corrupted or malformed artifact file."
                )
                if self._statsd:
                    self._statsd.increment(
                        "launchpad.artifact.processing.corruption_error"
                    )
                # Don't re-raise - let the consumer continue processing other messages
            else:
                logger.error(
                    f"Unexpected error processing artifact {artifact_id}: {e}",
                    exc_info=True,
                )
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
                logger.info(
                    f"Received signal {signum} during shutdown, forcing exit..."
                )
                # Force exit if we get a second signal
                os._exit(1)
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
        health_status = cast(
            HealthCheckResponse,
            {
                "service": "launchpad",
                "status": "ok",
                "components": {},
            },
        )

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
        health_status["components"]["server"] = {
            "status": "ok" if self.server else "not_initialized"
        }

        return health_status


def get_service_config() -> Dict[str, Any]:
    """Get service configuration from environment."""
    statsd_host = os.getenv("STATSD_HOST", "127.0.0.1")
    statsd_port_str = os.getenv("STATSD_PORT", "8125")
    sentry_base_url = os.getenv("SENTRY_BASE_URL")

    try:
        statsd_port = int(statsd_port_str)
    except ValueError:
        raise ValueError(f"STATSD_PORT must be a valid integer, got: {statsd_port_str}")

    return {
        "statsd_host": statsd_host,
        "statsd_port": statsd_port,
        "sentry_base_url": sentry_base_url,
    }


async def run_service() -> None:
    """Run the Launchpad service."""
    service = LaunchpadService()
    await service.setup()
    await service.start()


def _categorize_http_error(error_result: Dict[str, Any]) -> tuple[str, str]:
    """
    Categorize HTTP error results from SentryClient.

    Returns:
        Tuple of (error_category, error_description)
        Categories: "not_found", "server_error", "client_error", "unknown"
    """
    # First try to get the structured status code
    status_code = error_result.get("status_code")
    if isinstance(status_code, int):
        if status_code == 404:
            return "not_found", f"Resource not found (HTTP {status_code})"
        elif 500 <= status_code < 600:
            return "server_error", f"Server error (HTTP {status_code})"
        elif 400 <= status_code < 500:
            return "client_error", f"Client error (HTTP {status_code})"
        else:
            return "unknown", f"Unexpected HTTP status {status_code}"

    # Fallback to parsing the error message string
    error_msg = error_result.get("error", "")
    if isinstance(error_msg, str):
        # Extract HTTP status code from error message like "HTTP 404"
        match = re.search(r"HTTP (\d+)", error_msg)
        if match:
            try:
                status_code = int(match.group(1))
                if status_code == 404:
                    return "not_found", f"Resource not found (HTTP {status_code})"
                elif 500 <= status_code < 600:
                    return "server_error", f"Server error (HTTP {status_code})"
                elif 400 <= status_code < 500:
                    return "client_error", f"Client error (HTTP {status_code})"
                else:
                    return "unknown", f"Unexpected HTTP status {status_code}"
            except ValueError:
                pass

    return "unknown", f"Unknown error: {error_result}"
