"""Main service orchestrator for Launchpad."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import tempfile
import threading
import time

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, cast

import sentry_sdk

from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import PreprodArtifactEvents

from launchpad.api.update_api_models import AppleAppInfo as AppleAppInfoModel
from launchpad.api.update_api_models import PutSizeFailed, UpdateData
from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.android.apk import APK
from launchpad.artifacts.android.zipped_aab import ZippedAAB
from launchpad.artifacts.android.zipped_apk import ZippedAPK
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import AndroidArtifact, AppleArtifact, Artifact
from launchpad.artifacts.artifact_factory import ArtifactFactory
from launchpad.constants import (
    MAX_RETRY_ATTEMPTS,
    OPERATION_ERRORS,
    ArtifactType,
    OperationName,
    PreprodFeature,
    ProcessingErrorCode,
    ProcessingErrorMessage,
)
from launchpad.sentry_client import SentryClient, SentryClientError
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import BaseAppInfo
from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import NullStatsd, StatsdInterface, get_statsd

from .kafka import LaunchpadKafkaConsumer, create_kafka_consumer
from .sentry_sdk_init import initialize_sentry_sdk
from .server import LaunchpadServer, get_server_config
from .tracing import request_context

logger = get_logger(__name__)


def guess_message(code: ProcessingErrorCode, e: Exception) -> ProcessingErrorMessage:
    if code == ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR:
        if isinstance(e, NotImplementedError):
            return ProcessingErrorMessage.UNSUPPORTED_ARTIFACT_TYPE

    # If we can't guess from the exception but the code is set to
    # something useful return the matching message.
    if code == ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR:
        return ProcessingErrorMessage.ARTIFACT_PARSING_FAILED
    elif code == ProcessingErrorCode.ARTIFACT_PROCESSING_TIMEOUT:
        return ProcessingErrorMessage.PROCESSING_TIMEOUT
    else:
        # If all else fails return unknown
        return ProcessingErrorMessage.UNKNOWN_ERROR


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
        organization_id = payload["organization_id"]
        project_id = payload["project_id"]
        artifact_id = payload["artifact_id"]

        requested_features = []
        for feature in payload.get("requested_features", []):
            try:
                requested_features.append(PreprodFeature(feature))
            except ValueError:
                logger.exception(f"Unknown feature {feature}")

        if self._service_config and project_id in self._service_config.projects_to_skip:
            logger.info(f"Skipping processing for project {project_id}")
            return

        with contextlib.ExitStack() as stack:
            stack.enter_context(request_context())
            stack.enter_context(
                self._statsd.timed(
                    "artifact.processing.duration",
                    tags=[f"project_id:{project_id}", f"organization_id:{organization_id}"],
                )
            )
            scope = stack.enter_context(sentry_sdk.new_scope())
            scope.set_tag("launchpad.project_id", project_id)
            scope.set_tag("launchpad.organization_id", organization_id)
            scope.set_tag("launchpad.artifact_id", artifact_id)

            self._statsd.increment("artifact.processing.started")
            logger.info(f"Processing artifact {artifact_id} (project: {project_id}, org: {organization_id})")
            try:
                self.process_artifact(organization_id, project_id, artifact_id, requested_features)
            except Exception:
                self._statsd.increment("artifact.processing.failed")
                logger.exception(
                    f"Processing failed for artifact {artifact_id} (project: {project_id}, org: {organization_id})"
                )
            else:
                self._statsd.increment("artifact.processing.completed")
                logger.info(
                    f"Processing complete for artifact {artifact_id} (project: {project_id}, org: {organization_id})"
                )

    def process_artifact(
        self, organization_id: str, project_id: str, artifact_id: str, requested_features: list[PreprodFeature]
    ) -> None:
        dequeued_at = datetime.now()

        with contextlib.ExitStack() as stack:
            path = stack.enter_context(self._download_artifact(organization_id, project_id, artifact_id))
            artifact = self._parse_artifact(organization_id, project_id, artifact_id, path)
            analyzer = self._create_analyzer(artifact)

            info = self._preprocess_artifact(organization_id, project_id, artifact_id, artifact, analyzer, dequeued_at)

            if PreprodFeature.SIZE_ANALYSIS in requested_features:
                self._do_size(organization_id, project_id, artifact_id, artifact, analyzer)

            if PreprodFeature.BUILD_DISTRIBUTION in requested_features:
                self._do_distribution(organization_id, project_id, artifact_id, artifact, info)

    @contextlib.contextmanager
    def _download_artifact(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
    ) -> Iterator[Path]:
        logger.info(f"Downloading artifact {artifact_id} (project: {project_id}, org: {organization_id})")

        with tempfile.NamedTemporaryFile(suffix=".zip") as tf:
            with self._statsd.timed(
                "artifact.download.duration", tags=[f"project_id:{project_id}", f"organization_id:{organization_id}"]
            ):
                size = self._sentry_client.download_artifact(
                    org=organization_id,
                    project=project_id,
                    artifact_id=artifact_id,
                    out=tf,
                )
                logger.info(
                    f"Downloaded artifact {artifact_id} {size} bytes ({size / 1024 / 1024:.2f} MB) to {tf.name}"
                )
            yield Path(tf.name)

    def _parse_artifact(self, organization_id: str, project_id: str, artifact_id: str, path: Path) -> Artifact:
        try:
            return ArtifactFactory.from_path(path)
        except Exception as e:
            logger.exception("Failed to parse artifact")
            self._update_artifact_error_from_exception(
                organization_id,
                project_id,
                artifact_id,
                e,
                error_code=ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                error_message=ProcessingErrorMessage.ARTIFACT_PARSING_FAILED,
            )
            raise

    def _create_analyzer(self, artifact: AndroidArtifact | AppleArtifact) -> AndroidAnalyzer | AppleAppAnalyzer:
        if isinstance(artifact, AndroidArtifact):
            return AndroidAnalyzer()
        elif isinstance(artifact, AppleArtifact):
            return AppleAppAnalyzer()
        else:
            raise ValueError(f"Unknown artifact kind {artifact}")

    def _preprocess_artifact(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        artifact: Artifact,
        analyzer: AndroidAnalyzer | AppleAppAnalyzer,
        dequeued_at: datetime,
    ) -> AppleAppInfo | BaseAppInfo:
        logger.info(f"Preprocessing for {artifact_id} (project: {project_id}, org: {organization_id})")
        try:
            info = self._retry_operation(
                lambda: analyzer.preprocess(cast(Any, artifact)),
                OperationName.PREPROCESSING,
            )
            update_data = self._prepare_update_data(info, artifact, dequeued_at)
            self._sentry_client.update_artifact(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data=update_data,
            )
        except Exception as e:
            logger.exception(e)
            self._update_artifact_error_from_exception(
                organization_id,
                project_id,
                artifact_id,
                e,
                error_code=ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                error_message=ProcessingErrorMessage.PREPROCESSING_FAILED,
            )
            raise
        else:
            return info

    def _do_distribution(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        artifact: Artifact,
        info: AppleAppInfo | BaseAppInfo,
    ):
        logger.info(f"BUILD_DISTRIBUTION for {artifact_id} (project: {project_id}, org: {organization_id})")
        if isinstance(artifact, ZippedXCArchive):
            apple_info = cast(AppleAppInfo, info)
            if apple_info.is_code_signature_valid and not apple_info.is_simulator:
                with tempfile.TemporaryDirectory() as temp_dir_str:
                    temp_dir = Path(temp_dir_str)
                    ipa_path = temp_dir / "App.ipa"
                    artifact.generate_ipa(ipa_path)
                    with open(ipa_path, "rb") as f:
                        self._sentry_client.upload_installable_app(organization_id, project_id, artifact_id, f)
        elif isinstance(artifact, (AAB, ZippedAAB)):
            with tempfile.TemporaryDirectory() as temp_dir_str:
                temp_dir = Path(temp_dir_str)
                if isinstance(artifact, AAB):
                    universal_apk = artifact.get_universal_apk(temp_dir)
                else:  # ZippedAAB
                    universal_apk = artifact.get_aab().get_universal_apk(temp_dir)
                with universal_apk.raw_file() as f:
                    self._sentry_client.upload_installable_app(organization_id, project_id, artifact_id, f)
        elif isinstance(artifact, (APK, ZippedAPK)):
            if isinstance(artifact, ZippedAPK):
                apk = artifact.get_primary_apk()
            else:
                apk = artifact
            with apk.raw_file() as f:
                self._sentry_client.upload_installable_app(organization_id, project_id, artifact_id, f)
        else:
            # TODO: Should call _update_artifact_error here once we
            # support setting errors just for build.
            logger.error(f"BUILD_DISTRIBUTION failed for {artifact_id} (project: {project_id}, org: {organization_id})")

    def _do_size(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        artifact: Artifact,
        analyzer: AndroidAnalyzer | AppleAppAnalyzer,
    ):
        logger.info(f"SIZE_ANALYSIS for {artifact_id} (project: {project_id}, org: {organization_id})")
        try:
            results = self._retry_operation(
                lambda: analyzer.analyze(cast(Any, artifact)),
                OperationName.SIZE_ANALYSIS,
            )
            self._upload_results(organization_id, project_id, artifact_id, results)
        except Exception as e:
            logger.exception(f"SIZE_ANALYSIS failed artifact:{artifact_id} project:{project_id} org:{organization_id}")
            self._update_size_error_from_exception(
                organization_id,
                project_id,
                artifact_id,
                e,
                error_code=ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                error_message=ProcessingErrorMessage.SIZE_ANALYSIS_FAILED,
            )

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

                if isinstance(e, (ValueError, NotImplementedError, FileNotFoundError)):
                    logger.info(f"Non-retryable error for {operation_name.value}, not retrying")
                    break

                if attempt < MAX_RETRY_ATTEMPTS:
                    logger.info(f"Retrying {operation_name.value} in a moment...")
                    time.sleep(1)

        logger.error(f"All {MAX_RETRY_ATTEMPTS} attempts failed for {operation_name.value}")
        raise RuntimeError(f"{error_message.value}: {str(last_exception)}") from last_exception

    def _update_artifact_error_from_exception(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        e: Exception,
        error_code: ProcessingErrorCode = ProcessingErrorCode.UNKNOWN,
        error_message: ProcessingErrorMessage = ProcessingErrorMessage.UNKNOWN_ERROR,
    ) -> None:
        if error_message == ProcessingErrorMessage.UNKNOWN_ERROR:
            error_message = guess_message(error_code, e)

        self._update_artifact_error(organization_id, project_id, artifact_id, error_code, error_message, str(e))

    def _update_artifact_error(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        error_code: ProcessingErrorCode,
        error_message: ProcessingErrorMessage,
        detailed_error: str | None = None,
    ) -> None:
        """Update artifact with error information."""
        logger.info(f"Updating artifact {artifact_id} with error code {error_code.value}")

        message = f"{error_message.value}: {detailed_error}" if detailed_error else error_message.value

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
            self._sentry_client.update_artifact(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data={
                    "error_code": error_code.value,
                    "error_message": message,
                },
            )
        except SentryClientError:
            logger.exception(f"Failed to update artifact with error {message}")
        else:
            logger.info(f"Successfully updated artifact {artifact_id} with error information")

    def _update_size_error_from_exception(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        e: Exception,
        error_code: ProcessingErrorCode = ProcessingErrorCode.UNKNOWN,
        error_message: ProcessingErrorMessage = ProcessingErrorMessage.UNKNOWN_ERROR,
        identifier: str | None = None,
    ) -> None:
        if error_message == ProcessingErrorMessage.UNKNOWN_ERROR:
            error_message = guess_message(error_code, e)
        self._update_size_error(
            organization_id, project_id, artifact_id, error_code, error_message, str(e), identifier=identifier
        )

    def _update_size_error(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        error_code: ProcessingErrorCode,
        error_message: ProcessingErrorMessage,
        detailed_error: str | None = None,
        identifier: str | None = None,
    ) -> None:
        message = f"{error_message.value}: {detailed_error}" if detailed_error else error_message.value

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
            self._sentry_client.update_size_analysis(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data=PutSizeFailed(error_code=error_code.value, error_message=message),
                identifier=identifier,
            )
        except SentryClientError:
            logger.exception(f"Failed to update artifact with error {message}")

    def _prepare_update_data(
        self, app_info: AppleAppInfo | BaseAppInfo, artifact: Artifact, dequeued_at: datetime
    ) -> Dict[str, Any]:
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
            dequeued_at=dequeued_at,
        )

        return update_data.model_dump(exclude_none=True)

    def _upload_results(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        results: Any,
    ) -> None:
        try:
            with tempfile.TemporaryFile() as file:
                file.write(json.dumps(results.to_dict()).encode())
                file.seek(0)
                self._sentry_client.upload_size_analysis_file(
                    org=organization_id,
                    project=project_id,
                    artifact_id=artifact_id,
                    file=file,
                )
        except SentryClientError as e:
            logger.exception(e)
            self._update_artifact_error(
                organization_id,
                project_id,
                artifact_id,
                ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                ProcessingErrorMessage.UPLOAD_FAILED,
                e.user_facing_message(),
            )
            raise e
        else:
            logger.info(f"Successfully uploaded analysis results for artifact {artifact_id}")

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
