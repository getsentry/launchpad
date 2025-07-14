"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import tempfile
import time

from pathlib import Path
from typing import Any, Dict, cast

from arroyo.backends.kafka import KafkaPayload
from arroyo.processing.processor import StreamProcessor
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.constants import (
    HEALTHCHECK_MAX_AGE_SECONDS,
    MAX_RETRY_ATTEMPTS,
    OPERATION_ERRORS,
    ArtifactType,
    OperationName,
    ProcessingErrorCode,
    ProcessingErrorMessage,
)
from launchpad.sentry_client import ErrorResult, SentryClient, categorize_http_error
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.android import AndroidAppInfo
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.runner import do_preprocess, do_size
from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import DogStatsd, get_statsd

from .kafka import create_kafka_consumer
from .server import HealthCheckResponse, LaunchpadServer, get_server_config

logger = get_logger(__name__)


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
        self.kafka_processor = create_kafka_consumer(message_handler=self.handle_kafka_message)

        logger.info("Service components initialized")

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
            await self._shutdown_event.wait()
        finally:
            await self._cleanup(server_task)

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

            self.process_artifact(artifact_id, project_id, organization_id)

            logger.info(f"Analysis completed for artifact {artifact_id}")

            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.completed")

        except Exception as e:
            # Log the full error for debugging
            logger.error(
                f"Failed to process artifact {artifact_id} (project: {project_id}, org: {organization_id}): {e}",
                exc_info=True,
            )

            if self._statsd:
                self._statsd.increment("launchpad.artifact.processing.failed")

    def process_artifact(self, artifact_id: str, project_id: str, organization_id: str) -> None:
        """
        Download artifact and perform size analysis.
        """
        if not self._service_config:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        sentry_client = SentryClient(base_url=self._service_config["sentry_base_url"])
        temp_file = None

        try:
            temp_file = self._download_artifact_to_temp_file(sentry_client, artifact_id, project_id, organization_id)
            file_path = Path(temp_file)

            artifact = ArtifactFactory.from_path(Path(temp_file))
            logger.info(f"Running preprocessing on {temp_file}...")
            app_info = self._retry_operation(
                lambda: do_preprocess(file_path),
                OperationName.PREPROCESSING,
            )
            logger.info(f"Preprocessing completed for artifact {artifact_id}")

            update_data = self._prepare_update_data(app_info, artifact)
            logger.info(f"Sending preprocessed info to Sentry for artifact {artifact_id}...")
            update_result = sentry_client.update_artifact(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data=update_data,
            )

            # Check if update_result is an ErrorResult
            if isinstance(update_result, ErrorResult):
                error_category, error_description = categorize_http_error(update_result)
                error_msg = f"Failed to send preprocessed info: {error_description}"
                logger.error(error_msg)
                # Use the categorized error description for the database
                self._update_artifact_error(
                    sentry_client,
                    artifact_id,
                    project_id,
                    organization_id,
                    ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                    ProcessingErrorMessage.UPDATE_FAILED,
                    error_description,
                )
                return

            logger.info(f"Successfully sent preprocessed info for artifact {artifact_id}")

            artifact = ArtifactFactory.from_path(file_path)
            if isinstance(artifact, ZippedXCArchive):
                temp_dir = Path(tempfile.mkdtemp())
                ipa_path = temp_dir / "App.ipa"
                cast(ZippedXCArchive, artifact).generate_ipa(ipa_path)
                sentry_client.upload_installable_app(organization_id, project_id, artifact_id, str(ipa_path))
                self._safe_cleanup(str(ipa_path), "installable app")
                logger.info(f"Successfully uploaded installable app for artifact {artifact_id}")

            analyzer = self._create_analyzer(app_info)
            logger.info(f"Running full analysis on {temp_file}...")
            results = self._retry_operation(
                lambda: do_size(file_path, analyzer=analyzer),
                OperationName.SIZE_ANALYSIS,
            )
            logger.info(f"Size analysis completed for artifact {artifact_id}")

            self._upload_results(sentry_client, results, artifact_id, project_id, organization_id)

        except Exception as e:
            logger.error(f"Failed to process artifact {artifact_id}: {e}", exc_info=True)

            error_code, error_message = self._categorize_processing_error(e)

            # Include detailed error information for better debugging
            detailed_error = str(e)

            self._update_artifact_error(
                sentry_client, artifact_id, project_id, organization_id, error_code, error_message, detailed_error
            )
            raise

        finally:
            if temp_file:
                self._safe_cleanup(temp_file, "temporary file")

    def _retry_operation(self, operation, operation_name: OperationName):
        """Retry an operation up to MAX_RETRY_ATTEMPTS times."""
        error_message = OPERATION_ERRORS[operation_name]
        last_exception = None

        for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
            try:
                logger.debug(f"Attempting {operation_name.value} (attempt {attempt}/{MAX_RETRY_ATTEMPTS})")
                return operation()
            except Exception as e:
                last_exception = e
                logger.warning(f"{operation_name.value} failed on attempt {attempt}/{MAX_RETRY_ATTEMPTS}: {e}")

                if self._is_non_retryable_error(e):
                    logger.info(f"Non-retryable error for {operation_name.value}, not retrying")
                    break

                if attempt < MAX_RETRY_ATTEMPTS:
                    logger.info(f"Retrying {operation_name.value} in a moment...")
                    time.sleep(1)

        logger.error(f"All {MAX_RETRY_ATTEMPTS} attempts failed for {operation_name.value}")
        raise RuntimeError(f"{error_message.value}: {str(last_exception)}") from last_exception

    def _is_non_retryable_error(self, exception: Exception) -> bool:
        """Determine if an error should not be retried."""
        return isinstance(exception, (ValueError, NotImplementedError, FileNotFoundError))

    def _categorize_processing_error(self, exception: Exception) -> tuple[ProcessingErrorCode, ProcessingErrorMessage]:
        """Categorize an exception into error code and message."""
        if isinstance(exception, ValueError):
            return ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR, ProcessingErrorMessage.ARTIFACT_PARSING_FAILED
        elif isinstance(exception, NotImplementedError):
            return ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR, ProcessingErrorMessage.UNSUPPORTED_ARTIFACT_TYPE
        elif isinstance(exception, FileNotFoundError):
            return ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR, ProcessingErrorMessage.ARTIFACT_PARSING_FAILED
        elif isinstance(exception, RuntimeError):
            error_str = str(exception).lower()
            if "timeout" in error_str:
                return ProcessingErrorCode.ARTIFACT_PROCESSING_TIMEOUT, ProcessingErrorMessage.PROCESSING_TIMEOUT
            elif "preprocess" in error_str:
                return ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR, ProcessingErrorMessage.PREPROCESSING_FAILED
            elif "size" in error_str or "analysis" in error_str:
                return ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR, ProcessingErrorMessage.SIZE_ANALYSIS_FAILED
            else:
                return ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR, ProcessingErrorMessage.UNKNOWN_ERROR
        else:
            return ProcessingErrorCode.UNKNOWN, ProcessingErrorMessage.UNKNOWN_ERROR

    def _update_artifact_error(
        self,
        sentry_client: SentryClient,
        artifact_id: str,
        project_id: str,
        organization_id: str,
        error_code: ProcessingErrorCode,
        error_message: ProcessingErrorMessage,
        detailed_error: str | None = None,
    ) -> None:
        """Update artifact with error information."""
        try:
            logger.info(f"Updating artifact {artifact_id} with error code {error_code.value}")

            # Use detailed error message if provided, otherwise use enum value
            final_error_message = f"{error_message.value}: {detailed_error}" if detailed_error else error_message.value

            # Log error to datadog with tags for better monitoring
            if self._statsd:
                self._statsd.increment(
                    "launchpad.artifact.processing.error",
                    tags=[
                        f"error_code:{error_code.value}",
                        f"error_type:{error_message.name}",
                        f"project_id:{project_id}",
                        f"organization_id:{organization_id}",
                    ],
                )

            result = sentry_client.update_artifact(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data={"error_code": error_code.value, "error_message": final_error_message},
            )

            if isinstance(result, ErrorResult):
                logger.error(f"Failed to update artifact with error: {result.error}")
            else:
                logger.info(f"Successfully updated artifact {artifact_id} with error information")

        except Exception as e:
            logger.error(f"Failed to update artifact {artifact_id} with error information: {e}", exc_info=True)

    def _download_artifact_to_temp_file(
        self,
        sentry_client: SentryClient,
        artifact_id: str,
        project_id: str,
        organization_id: str,
    ) -> str:
        """Download artifact from Sentry directly to a temporary file."""
        logger.info(f"Downloading artifact {artifact_id}...")

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tf:
                temp_file = tf.name
                file_size = sentry_client.download_artifact_to_file(
                    org=organization_id, project=project_id, artifact_id=artifact_id, out=tf
                )

                # Success case
                logger.info(f"Downloaded artifact {artifact_id}: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)")
                logger.info(f"Saved artifact to temporary file: {temp_file}")
                return temp_file

        except Exception as e:
            # Handle all errors (download errors, temp file creation errors, I/O errors)
            error_msg = str(e)
            logger.error(error_msg)

            self._update_artifact_error(
                sentry_client,
                artifact_id,
                project_id,
                organization_id,
                ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                ProcessingErrorMessage.DOWNLOAD_FAILED,
                error_msg,
            )

            if temp_file:
                self._safe_cleanup(temp_file, "temporary file")
            raise

    def _prepare_update_data(self, app_info: AppleAppInfo | AndroidAppInfo, artifact: Any) -> Dict[str, Any]:
        """Prepare update data based on app platform and artifact type."""
        if isinstance(app_info, AppleAppInfo):
            # TODO: add "date_built" field once exposed in 'AppleAppInfo'
            return {
                "build_version": app_info.version,
                "build_number": (int(app_info.build) if str(app_info.build).isdigit() else app_info.build),
                "artifact_type": ArtifactType.XCARCHIVE.value,
                "apple_app_info": {
                    "is_simulator": app_info.is_simulator,
                    "codesigning_type": app_info.codesigning_type,
                    "profile_name": app_info.profile_name,
                    "is_code_signature_valid": app_info.is_code_signature_valid,
                    "code_signature_errors": app_info.code_signature_errors,
                },
            }
        elif isinstance(app_info, AndroidAppInfo):
            artifact_type = ArtifactType.AAB if isinstance(artifact, (AAB, ZippedAAB)) else ArtifactType.APK
            # TODO: add "date_built" and custom android fields
            return {
                "build_version": app_info.version,
                "build_number": (int(app_info.build) if app_info.build.isdigit() else None),
                "artifact_type": artifact_type.value,
            }
        else:
            raise ValueError(f"Unsupported app_info type: {type(app_info)}")

    def _create_analyzer(self, app_info: AppleAppInfo | AndroidAppInfo) -> AndroidAnalyzer | AppleAppAnalyzer:
        """Create analyzer with preprocessed app info."""
        if isinstance(app_info, AndroidAppInfo):
            analyzer = AndroidAnalyzer()
            analyzer.app_info = app_info
            return analyzer
        else:  # AppleAppInfo
            analyzer = AppleAppAnalyzer()
            analyzer.app_info = app_info
            return analyzer

    def _upload_results(
        self,
        sentry_client: SentryClient,
        results: Any,
        artifact_id: str,
        project_id: str,
        organization_id: str,
    ) -> None:
        """Upload analysis results to Sentry."""
        analysis_file = None

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as af:
                json.dump(results.to_dict(), af, indent=2)
                analysis_file = af.name

            logger.info(f"Analysis results written to temporary file: {analysis_file}")
            logger.info(f"Uploading analysis results for artifact {artifact_id}...")

            upload_result = sentry_client.upload_size_analysis_file(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                file_path=analysis_file,
            )

            if isinstance(upload_result, ErrorResult):
                error_category, error_description = categorize_http_error(upload_result)
                error_msg = f"Failed to upload analysis results: {error_description}"
                logger.error(error_msg)
                # Use the categorized error description for the database
                self._update_artifact_error(
                    sentry_client,
                    artifact_id,
                    project_id,
                    organization_id,
                    ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                    ProcessingErrorMessage.UPLOAD_FAILED,
                    error_description,
                )
                raise RuntimeError(error_msg)

            logger.info(f"Successfully uploaded analysis results for artifact {artifact_id}")

        except Exception as e:
            if not isinstance(e, RuntimeError):
                detailed_error = str(e)
                self._update_artifact_error(
                    sentry_client,
                    artifact_id,
                    project_id,
                    organization_id,
                    ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                    ProcessingErrorMessage.UPLOAD_FAILED,
                    detailed_error,
                )
            raise

        finally:
            if analysis_file:
                self._safe_cleanup(analysis_file, "analysis file")

    def _safe_cleanup(self, file_path: str, description: str) -> None:
        """Safely clean up a file with error handling."""
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.debug(f"Cleaned up {description}: {file_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up {description} {file_path}: {e}")

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""

        def signal_handler(signum: int, frame: Any) -> None:
            if self._shutdown_event.is_set():
                logger.info(f"Received signal {signum} during shutdown, forcing exit...")
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
        health_status["components"]["server"] = {"status": "ok" if self.server else "not_initialized"}

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
