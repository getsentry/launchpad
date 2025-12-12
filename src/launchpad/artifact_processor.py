from __future__ import annotations

import contextlib
import json
import tempfile
import time

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, cast

import sentry_sdk

from objectstore_client import (
    Client as ObjectstoreClient,
)
from objectstore_client import (
    Usecase,
)
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.api.update_api_models import AndroidAppInfo as AndroidAppInfoModel
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
    ArtifactType,
    PreprodFeature,
    ProcessingErrorCode,
    ProcessingErrorMessage,
)
from launchpad.sentry_client import SentryClient, SentryClientError
from launchpad.sentry_sdk_init import initialize_sentry_sdk
from launchpad.size.analyzers.android import AndroidAnalyzer
from launchpad.size.analyzers.apple import AppleAppAnalyzer
from launchpad.size.models.android import AndroidAppInfo
from launchpad.size.models.apple import AppleAppInfo
from launchpad.size.models.common import BaseAppInfo
from launchpad.tracing import request_context
from launchpad.utils.file_utils import IdPrefix, id_from_bytes
from launchpad.utils.logging import get_logger
from launchpad.utils.statsd import StatsdInterface, get_statsd

logger = get_logger(__name__)


class ArtifactProcessor:
    def __init__(
        self,
        sentry_client: SentryClient,
        statsd: StatsdInterface,
        objectstore_client: ObjectstoreClient | None,
    ) -> None:
        self._sentry_client = sentry_client
        self._statsd = statsd
        self._objectstore_client = objectstore_client
        self._objectstore_usecase = Usecase(name="preprod")

    @staticmethod
    def process_message(
        payload: PreprodArtifactEvents,
        service_config=None,
        artifact_processor=None,
        statsd=None,
    ):
        """Process an artifact message with proper context and metrics.
        This is used by the Kafka workers and so has to set up the context from scratch.
        If components are not provided, they will be created.
        """
        start_time = time.time()

        if service_config is None:
            from launchpad.service import get_service_config

            service_config = get_service_config()

        initialize_sentry_sdk()

        organization_id = payload["organization_id"]
        project_id = payload["project_id"]
        artifact_id = payload["artifact_id"]

        if statsd is None:
            statsd = get_statsd()
        if artifact_processor is None:
            sentry_client = SentryClient(base_url=service_config.sentry_base_url)
            objectstore_client = None
            if service_config.objectstore_url is not None:
                objectstore_client = ObjectstoreClient(service_config.objectstore_url)
            artifact_processor = ArtifactProcessor(sentry_client, statsd, objectstore_client)

        requested_features = []
        for feature in payload.get("requested_features", []):
            try:
                requested_features.append(PreprodFeature(feature))
            except ValueError:
                logger.exception(f"Unknown feature {feature}")

        if service_config and project_id in service_config.projects_to_skip:
            logger.info(f"Skipping processing for project {project_id}")
            return

        with contextlib.ExitStack() as stack:
            stack.enter_context(request_context())
            stack.enter_context(
                statsd.timed(
                    "artifact.processing.duration",
                    tags=[
                        f"project_id:{project_id}",
                        f"organization_id:{organization_id}",
                    ],
                )
            )
            scope = stack.enter_context(sentry_sdk.new_scope())
            scope.set_tag("launchpad.project_id", project_id)
            scope.set_tag("launchpad.organization_id", organization_id)
            scope.set_tag("launchpad.artifact_id", artifact_id)
            stack.enter_context(scope.start_transaction(op="subprocess", name="launchpad.process_message"))
            statsd.increment("artifact.processing.started")
            logger.info(f"Processing artifact {artifact_id} (project: {project_id}, org: {organization_id})")
            try:
                artifact_processor.process_artifact(organization_id, project_id, artifact_id, requested_features)
            except Exception:
                statsd.increment("artifact.processing.failed")
                duration = time.time() - start_time
                logger.exception(
                    f"Processing failed for artifact {artifact_id} (project: {project_id}, org: {organization_id}) in {duration:.2f}s"
                )
            else:
                statsd.increment("artifact.processing.completed")
                duration = time.time() - start_time
                logger.info(
                    f"Processing complete for artifact {artifact_id} (project: {project_id}, org: {organization_id}) in {duration:.2f}s"
                )

    def process_artifact(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        requested_features: list[PreprodFeature],
    ) -> None:
        """Process an artifact with the requested features."""
        dequeued_at = datetime.now()

        with contextlib.ExitStack() as stack:
            path = stack.enter_context(self._download_artifact(organization_id, project_id, artifact_id))
            artifact = self._parse_artifact(organization_id, project_id, artifact_id, path)
            analyzer = self._create_analyzer(artifact)
            app_icon_object_id = self._process_app_icon(organization_id, project_id, artifact_id, artifact)
            info = self._preprocess_artifact(
                organization_id,
                project_id,
                artifact_id,
                artifact,
                analyzer,
                dequeued_at,
                app_icon_object_id,
            )

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
                "artifact.download.duration",
                tags=[f"project_id:{project_id}", f"organization_id:{organization_id}"],
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
        app_icon_id: str | None,
    ) -> AppleAppInfo | BaseAppInfo:
        logger.info(f"Preprocessing for {artifact_id} (project: {project_id}, org: {organization_id})")
        try:
            info = analyzer.preprocess(cast(Any, artifact))
            update_data = self._prepare_update_data(info, artifact, dequeued_at, app_icon_id)
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

    def _process_app_icon(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        artifact: Artifact,
    ) -> str | None:
        if self._objectstore_client is None:
            logger.info(
                f"No objectstore client found for {artifact_id} (project: {project_id}, org: {organization_id})"
            )
            return None

        logger.info(f"Processing app icon for {artifact_id} (project: {project_id}, org: {organization_id})")
        app_icon = artifact.get_app_icon()
        if app_icon is None:
            logger.info(f"No app icon found for {artifact_id} (project: {project_id}, org: {organization_id})")
            return None

        image_id = id_from_bytes(app_icon, IdPrefix.ICON)
        icon_key = f"{organization_id}/{project_id}/{image_id}"
        logger.info(f"Uploading app icon to object store: {icon_key}")
        session = self._objectstore_client.session(self._objectstore_usecase, org=organization_id, project=project_id)
        session.put(app_icon, id=icon_key)
        return image_id

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
            # TODO(EME-422): Should call _update_artifact_error here once we
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
        logger.info(f"SIZE_ANALYSIS for {artifact_id} (project: {project_id}, org: {organization_id}) started")
        try:
            results = analyzer.analyze(cast(Any, artifact))
            self._upload_results(organization_id, project_id, artifact_id, results)
        except Exception as e:
            logger.exception(
                f"SIZE_ANALYSIS for artifact:{artifact_id} project:{project_id} org:{organization_id} failed"
            )
            self._update_size_error_from_exception(
                organization_id,
                project_id,
                artifact_id,
                e,
                error_code=ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
                error_message=ProcessingErrorMessage.SIZE_ANALYSIS_FAILED,
            )
        else:
            logger.info(f"SIZE_ANALYSIS for {artifact_id} (project: {project_id}, org: {organization_id}) succeeded")

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
            error_message = _guess_message(error_code, e)

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
            error_message = _guess_message(error_code, e)
        self._update_size_error(
            organization_id,
            project_id,
            artifact_id,
            error_code,
            error_message,
            str(e),
            identifier=identifier,
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
        self,
        app_info: AppleAppInfo | BaseAppInfo,
        artifact: Artifact,
        dequeued_at: datetime,
        app_icon_id: str | None,
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
            apple_app_info = AppleAppInfoModel(
                is_simulator=app_info.is_simulator,
                codesigning_type=app_info.codesigning_type,
                profile_name=app_info.profile_name,
                is_code_signature_valid=app_info.is_code_signature_valid,
                code_signature_errors=app_info.code_signature_errors,
                main_binary_uuid=app_info.main_binary_uuid,
                profile_expiration_date=app_info.profile_expiration_date,
                certificate_expiration_date=app_info.certificate_expiration_date,
                missing_dsym_binaries=app_info.missing_dsym_binaries,
                build_date=app_info.build_date,
            )

        android_app_info = None
        if isinstance(app_info, AndroidAppInfo):
            android_app_info = AndroidAppInfoModel(
                has_proguard_mapping=app_info.has_proguard_mapping,
            )

        update_data = UpdateData(
            app_name=app_info.name,
            app_id=app_info.app_id,
            build_version=app_info.version,
            build_number=build_number,
            artifact_type=_get_artifact_type(artifact).value,
            apple_app_info=apple_app_info,
            android_app_info=android_app_info,
            dequeued_at=dequeued_at,
            app_icon_id=app_icon_id,
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


def _guess_message(code: ProcessingErrorCode, e: Exception) -> ProcessingErrorMessage:
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
