"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import tempfile
import threading
import time

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, cast

from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.api.update_api_models import AppleAppInfo as AppleAppInfoModel
from launchpad.api.update_api_models import UpdateData
from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import Artifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.constants import (
    MAX_RETRY_ATTEMPTS,
    OPERATION_ERRORS,
    ArtifactType,
    OperationName,
    ProcessingErrorCode,
    ProcessingErrorMessage,
)
from launchpad.sentry_client import SentryClient, SentryClientError
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import BaseAppInfo
from launchpad.size.runner import do_preprocess, do_size
from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import DogStatsd, get_statsd

from .kafka import LaunchpadKafkaConsumer, create_kafka_consumer
from .sentry_sdk_init import initialize_sentry_sdk
from .server import LaunchpadServer, get_server_config

logger = get_logger(__name__)


class LaunchpadService:
    """Main service that orchestrates HTTP server and Kafka consumer."""

    def __init__(self) -> None:
        self.server: LaunchpadServer | None = None
        self.kafka: LaunchpadKafkaConsumer | None = None
        self._kafka_task: asyncio.Future[Any] | None = None
        self._statsd: DogStatsd | None = None
        self._healthcheck_file: str | None = None
        self._service_config: ServiceConfig | None = None

    async def setup(self) -> None:
        """Set up the service components."""
        self._service_config = get_service_config()
        self._statsd = get_statsd()
        initialize_sentry_sdk()

        server_config = get_server_config()
        self.server = LaunchpadServer(
            self.is_healthy,
            host=server_config.host,
            port=server_config.port,
        )

        self.kafka = create_kafka_consumer(message_handler=self.handle_kafka_message)

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
                self._statsd.increment("artifact.processing.started")

                timing_tags = [f"project_id:{project_id}", f"organization_id:{organization_id}"]
                with self._statsd.timed("artifact.processing.duration", tags=timing_tags):
                    self.process_artifact(artifact_id, project_id, organization_id)
            else:
                self.process_artifact(artifact_id, project_id, organization_id)

            logger.info(f"Analysis completed for artifact {artifact_id}")

            if self._statsd:
                self._statsd.increment("artifact.processing.completed")

        except Exception as e:
            # Log the full error for debugging
            logger.error(
                f"Failed to process artifact {artifact_id} (project: {project_id}, org: {organization_id}): {e}",
                exc_info=True,
            )

            if self._statsd:
                self._statsd.increment("artifact.processing.failed")

    def process_artifact(self, artifact_id: str, project_id: str, organization_id: str) -> None:
        """
        Download artifact and perform size analysis.
        """
        if not self._service_config:
            raise RuntimeError("Service not properly initialized. Call setup() first.")

        sentry_client = SentryClient(base_url=self._service_config.sentry_base_url)
        temp_file = None
        artifact = None

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
            try:
                sentry_client.update_artifact(
                    org=organization_id,
                    project=project_id,
                    artifact_id=artifact_id,
                    data=update_data,
                )
            except SentryClientError as e:
                logger.exception(e)
                self._update_artifact_error(
                    sentry_client,
                    artifact_id,
                    project_id,
                    organization_id,
                    ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                    ProcessingErrorMessage.UPDATE_FAILED,
                    e.user_facing_message(),
                )
                return
            else:
                logger.info(f"Successfully sent preprocessed info for artifact {artifact_id}")

            if isinstance(artifact, ZippedXCArchive) and app_info.is_code_signature_valid and not app_info.is_simulator:
                with tempfile.TemporaryDirectory() as temp_dir_str:
                    temp_dir = Path(temp_dir_str)
                    ipa_path = temp_dir / "App.ipa"
                    cast(ZippedXCArchive, artifact).generate_ipa(ipa_path)
                    with open(ipa_path, "rb") as f:
                        sentry_client.upload_installable_app(organization_id, project_id, artifact_id, f)
                    logger.info(f"Successfully uploaded installable app for artifact {artifact_id}")
            elif isinstance(artifact, (AAB, ZippedAAB)):
                with tempfile.TemporaryDirectory() as temp_dir_str:
                    temp_dir = Path(temp_dir_str)
                    if isinstance(artifact, AAB):
                        universal_apk = artifact.get_universal_apk(temp_dir)
                    else:  # ZippedAAB
                        universal_apk = artifact.get_aab().get_universal_apk(temp_dir)
                    with universal_apk.raw_file() as f:
                        sentry_client.upload_installable_app(organization_id, project_id, artifact_id, f)
                    logger.info(f"Successfully uploaded installable app for artifact {artifact_id}")
            elif isinstance(artifact, (APK, ZippedAPK)):
                if isinstance(artifact, ZippedAPK):
                    apk = artifact.get_primary_apk()
                else:
                    apk = artifact

                with apk.raw_file() as f:
                    sentry_client.upload_installable_app(organization_id, project_id, artifact_id, f)
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
                sentry_client,
                artifact_id,
                project_id,
                organization_id,
                error_code,
                error_message,
                detailed_error,
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
            return (
                ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                ProcessingErrorMessage.ARTIFACT_PARSING_FAILED,
            )
        elif isinstance(exception, NotImplementedError):
            return (
                ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                ProcessingErrorMessage.UNSUPPORTED_ARTIFACT_TYPE,
            )
        elif isinstance(exception, FileNotFoundError):
            return (
                ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                ProcessingErrorMessage.ARTIFACT_PARSING_FAILED,
            )
        elif isinstance(exception, RuntimeError):
            error_str = str(exception).lower()
            if "timeout" in error_str:
                return (
                    ProcessingErrorCode.ARTIFACT_PROCESSING_TIMEOUT,
                    ProcessingErrorMessage.PROCESSING_TIMEOUT,
                )
            elif "preprocess" in error_str:
                return (
                    ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                    ProcessingErrorMessage.PREPROCESSING_FAILED,
                )
            elif "size" in error_str or "analysis" in error_str:
                return (
                    ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                    ProcessingErrorMessage.SIZE_ANALYSIS_FAILED,
                )
            else:
                return (
                    ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                    ProcessingErrorMessage.UNKNOWN_ERROR,
                )
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
        logger.info(f"Updating artifact {artifact_id} with error code {error_code.value}")

        # Use detailed error message if provided, otherwise use enum value
        final_error_message = f"{error_message.value}: {detailed_error}" if detailed_error else error_message.value

        # Log error to datadog with tags for better monitoring
        if self._statsd:
            self._statsd.increment(
                "artifact.processing.error",
                tags=[
                    f"error_code:{error_code.value}",
                    f"error_type:{error_message.name}",
                    f"project_id:{project_id}",
                    f"organization_id:{organization_id}",
                ],
            )

        try:
            sentry_client.update_artifact(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data={
                    "error_code": error_code.value,
                    "error_message": final_error_message,
                },
            )
        except SentryClientError as e:
            logger.error(f"Failed to update artifact with error {final_error_message} due to {e}", exc_info=True)
        else:
            logger.info(f"Successfully updated artifact {artifact_id} with error information")

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

                timing_tags = [f"project_id:{project_id}", f"organization_id:{organization_id}"]
                if self._statsd:
                    with self._statsd.timed("artifact.download.duration", tags=timing_tags):
                        file_size = sentry_client.download_artifact_to_file(
                            org=organization_id,
                            project=project_id,
                            artifact_id=artifact_id,
                            out=tf,
                        )
                else:
                    file_size = sentry_client.download_artifact_to_file(
                        org=organization_id,
                        project=project_id,
                        artifact_id=artifact_id,
                        out=tf,
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

    def _prepare_update_data(self, app_info: AppleAppInfo | BaseAppInfo, artifact: Artifact) -> Dict[str, Any]:
        def _get_artifact_type(artifact: Artifact) -> ArtifactType:
            if isinstance(artifact, ZippedXCArchive):
                return ArtifactType.XCARCHIVE
            elif isinstance(artifact, (AAB, ZippedAAB)):
                return ArtifactType.AAB
            elif isinstance(artifact, (APK, ZippedAPK)):
                return ArtifactType.APK
            else:
                raise ValueError(f"Unsupported artifact type: {type(artifact)}")

        build_number = int(app_info.build) if app_info.build.isdigit() else None

        apple_app_info = None
        if isinstance(app_info, AppleAppInfo):
            # TODO: add "date_built" field once exposed in 'AppleAppInfo'
            apple_app_info = AppleAppInfoModel(
                is_simulator=app_info.is_simulator,
                codesigning_type=app_info.codesigning_type,
                profile_name=app_info.profile_name,
                is_code_signature_valid=app_info.is_code_signature_valid,
                code_signature_errors=app_info.code_signature_errors,
                main_binary_uuid=app_info.main_binary_uuid,
                profile_expiration_date=app_info.profile_expiration_date,
                certificate_expiration_date=app_info.certificate_expiration_date,
            )
        # TODO: add "date_built" and custom android fields

        update_data = UpdateData(
            app_name=app_info.name,
            app_id=app_info.app_id,
            build_version=app_info.version,
            build_number=build_number,
            artifact_type=_get_artifact_type(artifact).value,
            apple_app_info=apple_app_info,
        )

        return update_data.dict(exclude_none=True)

    def _create_analyzer(self, app_info: AppleAppInfo | BaseAppInfo) -> AndroidAnalyzer | AppleAppAnalyzer:
        """Create analyzer with preprocessed app info."""
        if isinstance(app_info, AppleAppInfo):
            analyzer = AppleAppAnalyzer()
            analyzer.app_info = app_info
            return analyzer
        else:  # Android
            analyzer = AndroidAnalyzer()
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
        try:
            with tempfile.TemporaryFile() as file:
                file.write(json.dumps(results.to_dict()).encode())
                file.seek(0)
                sentry_client.upload_size_analysis_file(
                    org=organization_id,
                    project=project_id,
                    artifact_id=artifact_id,
                    file=file,
                )
        except SentryClientError as e:
            logger.exception(e)
            self._update_artifact_error(
                sentry_client,
                artifact_id,
                project_id,
                organization_id,
                ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                ProcessingErrorMessage.UPLOAD_FAILED,
                e.user_facing_message(),
            )
            raise e
        else:
            logger.info(f"Successfully uploaded analysis results for artifact {artifact_id}")

    def _safe_cleanup(self, file_path: str, description: str) -> None:
        """Safely clean up a file with error handling."""
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.debug(f"Cleaned up {description}: {file_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up {description} {file_path}: {e}")

    def is_healthy(self) -> bool:
        """Get overall service health status."""
        is_server_healthy = self.server.is_healthy()
        is_kafka_healthy = self.kafka.is_healthy()
        return is_server_healthy and is_kafka_healthy


@dataclass
class ServiceConfig:
    """Service configuration data."""

    sentry_base_url: str


def get_service_config() -> ServiceConfig:
    """Get service configuration from environment."""
    sentry_base_url = os.getenv("SENTRY_BASE_URL")
    if sentry_base_url is None:
        sentry_base_url = "http://getsentry.default"

    return ServiceConfig(
        sentry_base_url=sentry_base_url,
    )


async def run_service() -> None:
    """Run the Launchpad service."""
    service = LaunchpadService()
    await service.setup()
    await service.start()
