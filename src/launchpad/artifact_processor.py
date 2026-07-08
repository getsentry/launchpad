from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, cast

import sentry_sdk

from objectstore_client import (
    Client as ObjectstoreClient,
)
from objectstore_client import (
    Usecase,
)
from objectstore_client.metadata import TimeToLive
from taskbroker_client.worker.workerchild import ProcessingDeadlineExceeded

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
    InstallableAppErrorCode,
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
from launchpad.utils.objectstore import ObjectstoreConfig, create_objectstore_client
from launchpad.utils.statsd import StatsdInterface, get_statsd

logger = get_logger(__name__)


@dataclass
class ServiceConfig:
    sentry_base_url: str
    projects_to_skip: list[str]
    objectstore_config: ObjectstoreConfig


def get_service_config() -> ServiceConfig:
    sentry_base_url = os.getenv("SENTRY_BASE_URL")
    projects_to_skip_str = os.getenv("PROJECT_IDS_TO_SKIP")
    projects_to_skip = projects_to_skip_str.split(",") if projects_to_skip_str else []

    objectstore_config = ObjectstoreConfig(
        objectstore_url=os.getenv("OBJECTSTORE_URL"),
        key_id=os.getenv("OBJECTSTORE_SIGNING_KEY_ID"),
        key_file=os.getenv("OBJECTSTORE_SIGNING_KEY_FILE"),
    )
    if expiry_seconds := os.getenv("OBJECTSTORE_TOKEN_EXPIRY_SECONDS"):
        objectstore_config.token_expiry_seconds = int(expiry_seconds)

    if sentry_base_url is None:
        sentry_base_url = "http://getsentry.default"

    return ServiceConfig(
        sentry_base_url=sentry_base_url,
        projects_to_skip=projects_to_skip,
        objectstore_config=objectstore_config,
    )


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
        artifact_id: str,
        project_id: str,
        organization_id: str,
        service_config=None,
        artifact_processor=None,
        statsd=None,
    ):
        """Process an artifact message with proper context and metrics.
        If components are not provided, they will be created.
        """
        start_time = time.time()

        if service_config is None:
            service_config = get_service_config()

        initialize_sentry_sdk()

        if statsd is None:
            statsd = get_statsd()
        if artifact_processor is None:
            sentry_client = SentryClient(base_url=service_config.sentry_base_url)
            objectstore_client = create_objectstore_client(service_config.objectstore_config)
            artifact_processor = ArtifactProcessor(sentry_client, statsd, objectstore_client)

        if service_config and project_id in service_config.projects_to_skip:
            logger.info(f"Skipping processing for project {project_id}")
            return

        artifact_type = "unknown"
        with contextlib.ExitStack() as stack:
            stack.enter_context(request_context())
            processing_start = time.monotonic()
            scope = stack.enter_context(sentry_sdk.new_scope())
            scope.set_tag("launchpad.project_id", project_id)
            scope.set_tag("launchpad.organization_id", organization_id)
            scope.set_tag("launchpad.preprod_artifact_id", artifact_id)
            stack.enter_context(scope.start_transaction(op="subprocess", name="launchpad.process_message"))
            statsd.increment("artifact.processing.started")
            logger.info(f"Processing artifact {artifact_id} (project: {project_id}, org: {organization_id})")
            try:
                artifact_type = artifact_processor.process_artifact(organization_id, project_id, artifact_id)
            except ProcessingDeadlineExceeded:
                statsd.increment("artifact.processing.failed")
                statsd.increment("artifact.processing.timeout")
                duration = time.time() - start_time
                logger.error(
                    f"Processing timed out for artifact {artifact_id} (project: {project_id}, org: {organization_id}) after {duration:.2f}s"
                )
                artifact_processor._update_artifact_error(
                    organization_id,
                    project_id,
                    artifact_id,
                    ProcessingErrorCode.ARTIFACT_PROCESSING_TIMEOUT,
                    ProcessingErrorMessage.PROCESSING_TIMEOUT,
                )
                raise
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
            finally:
                statsd.timing(
                    "artifact.processing.duration",
                    time.monotonic() - processing_start,
                    tags=[
                        f"project_id:{project_id}",
                        f"organization_id:{organization_id}",
                        f"artifact_type:{artifact_type}",
                    ],
                )

    def process_artifact(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
    ) -> str:
        """Process an artifact and return the artifact type string."""
        dequeued_at = datetime.now()

        with contextlib.ExitStack() as stack:
            path = stack.enter_context(self._download_artifact(organization_id, project_id, artifact_id))
            artifact = self._parse_artifact(organization_id, project_id, artifact_id, path)
            analyzer = self._create_analyzer(artifact)
            retention = self._sentry_client.get_retention(organization_id)
            retention_days = max(retention.size, retention.build_distribution)
            try:
                app_icon_object_id = self._process_app_icon(
                    organization_id, project_id, artifact_id, artifact, retention_days
                )
            except Exception:
                logger.exception(
                    f"Failed to process app icon for artifact {artifact_id} (project: {project_id}, org: {organization_id})"
                )
                app_icon_object_id = None
            info, server_requested_features = self._preprocess_artifact(
                organization_id,
                project_id,
                artifact_id,
                artifact,
                analyzer,
                dequeued_at,
                app_icon_object_id,
            )

            if PreprodFeature.SIZE_ANALYSIS in server_requested_features:
                self._do_size(organization_id, project_id, artifact_id, artifact, analyzer)

            if PreprodFeature.BUILD_DISTRIBUTION in server_requested_features:
                self._do_distribution(organization_id, project_id, artifact_id, artifact, info)

            return _get_artifact_type(artifact).name.lower()

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
                file_size = self._sentry_client.download_artifact(
                    org=organization_id,
                    project=project_id,
                    artifact_id=artifact_id,
                    out=tf,
                )
                logger.info(
                    f"Downloaded artifact {artifact_id} {file_size} bytes ({file_size / 1024 / 1024:.2f} MB) to {tf.name}"
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
    ) -> tuple[AppleAppInfo | BaseAppInfo, list[PreprodFeature]]:
        logger.info(f"Preprocessing for {artifact_id} (project: {project_id}, org: {organization_id})")
        try:
            info = analyzer.preprocess(cast(Any, artifact))
            update_data = self._prepare_update_data(info, artifact, dequeued_at, app_icon_id)
            response = self._sentry_client.update_artifact(
                org=organization_id,
                project=project_id,
                artifact_id=artifact_id,
                data=update_data,
            )
            logger.info(
                f"Requested features for {artifact_id} (project: {project_id}, org: {organization_id}): {response.requested_features}"
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
            return info, response.requested_features

    def _process_app_icon(
        self,
        organization_id: str,
        project_id: str,
        artifact_id: str,
        artifact: Artifact,
        retention_days: int,
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
        session.put(
            app_icon,
            key=icon_key,
            expiration_policy=TimeToLive(delta=timedelta(days=retention_days)),
        )
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
            if not apple_info.is_code_signature_valid:
                logger.warning(f"BUILD_DISTRIBUTION skipped for {artifact_id}: invalid code signature")
                self._update_distribution_error(
                    organization_id,
                    artifact_id,
                    InstallableAppErrorCode.INVALID_CODE_SIGNATURE,
                    "The build's code signature could not be verified.",
                )
                return
            if apple_info.is_simulator:
                logger.warning(f"BUILD_DISTRIBUTION skipped for {artifact_id}: simulator build")
                self._update_distribution_error(
                    organization_id,
                    artifact_id,
                    InstallableAppErrorCode.SIMULATOR_BUILD,
                    "Simulator builds cannot be distributed.",
                )
                return
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
            logger.error(f"BUILD_DISTRIBUTION failed for {artifact_id}: unsupported artifact type")
            self._update_distribution_error(
                organization_id,
                artifact_id,
                InstallableAppErrorCode.UNSUPPORTED_ARTIFACT_TYPE,
                "This artifact type is not supported for distribution.",
            )

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

    def _update_distribution_error(
        self,
        organization_id: str,
        artifact_id: str,
        error_code: InstallableAppErrorCode,
        error_message: str,
    ) -> None:
        """Update distribution with error/skip information."""
        logger.info(f"Updating distribution for {artifact_id} with error code {error_code.value}")

        self._statsd.increment(
            "distribution.processing.error",
            tags=[
                f"error_code:{error_code.value}",
                f"organization_id:{organization_id}",
            ],
        )

        try:
            self._sentry_client.update_distribution(
                org=organization_id,
                artifact_id=artifact_id,
                data={
                    "error_code": error_code.value,
                    "error_message": error_message,
                },
            )
        except SentryClientError:
            logger.exception(f"Failed to update distribution error for artifact {artifact_id}")
        else:
            logger.info(f"Successfully updated distribution for {artifact_id} with error information")

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
    ) -> dict[str, Any]:
        build_number = _parse_build_number(app_info.build)

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
                cli_version=app_info.cli_version,
                fastlane_plugin_version=app_info.fastlane_plugin_version,
            )

        android_app_info = None
        if isinstance(app_info, AndroidAppInfo):
            android_app_info = AndroidAppInfoModel(
                has_proguard_mapping=app_info.has_proguard_mapping,
                cli_version=app_info.cli_version,
                gradle_plugin_version=app_info.gradle_plugin_version,
            )

        update_data = UpdateData(
            app_name=app_info.name,
            app_id=app_info.app_id,
            build_version=app_info.version,
            build_number=build_number,
            build_number_raw=app_info.build,
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
            raise
        else:
            logger.info(f"Successfully uploaded analysis results for artifact {artifact_id}")


def _get_artifact_type(artifact: Artifact) -> ArtifactType:
    if isinstance(artifact, ZippedXCArchive):
        return ArtifactType.XCARCHIVE
    elif isinstance(artifact, (AAB, ZippedAAB)):
        return ArtifactType.AAB
    elif isinstance(artifact, (APK, ZippedAPK)):
        return ArtifactType.APK
    else:
        raise ValueError(f"Unsupported artifact type: {type(artifact)}")


def _guess_message(code: ProcessingErrorCode, e: Exception) -> ProcessingErrorMessage:
    if code == ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR:
        if isinstance(e, NotImplementedError):
            return ProcessingErrorMessage.UNSUPPORTED_ARTIFACT_TYPE
        return ProcessingErrorMessage.ARTIFACT_PARSING_FAILED
    elif code == ProcessingErrorCode.ARTIFACT_PROCESSING_TIMEOUT:
        return ProcessingErrorMessage.PROCESSING_TIMEOUT
    return ProcessingErrorMessage.UNKNOWN_ERROR


# Zero-padding width per CFBundleVersion component when packing it into a single
# sortable int. 6 digits comfortably covers any realistic CI build counter while
# leaving the packed value well under BoundedBigIntegerField's max (bigint).
_BUILD_NUMBER_COMPONENT_WIDTH = 6


def _parse_build_number(build: str) -> int | None:
    """Parse a raw build identifier (e.g. CFBundleVersion) into a sortable int.

    Plain integer builds (the common case, e.g. Android versionCode) pass through
    unchanged. Apple's CFBundleVersion also allows up to three dot-separated
    non-negative integers (e.g. "1.2.3"); those are packed into a single int by
    zero-padding each component, which preserves correct ordering as long as no
    component reaches 10**_BUILD_NUMBER_COMPONENT_WIDTH. Anything else
    (non-numeric, malformed) returns None, same as today.

    Known limitation: plain-integer values are left small while packed dotted
    values are much larger, so if the same app_id/build_version ever has builds
    in both conventions, this int alone is not a reliable ordering between them.
    We can't fix that here — a single artifact update has no visibility into
    sibling artifacts' formats, and unifying the magnitude would break backward
    compatibility with every already-stored plain-integer build_number. Sentry's
    tiebreak query should treat this as a fast, common-case sort key and fall
    back to comparing the raw build string (build_number_raw) directly when it
    needs to be authoritative across mixed formats.
    """
    if build.isdigit():
        return int(build)

    parts = build.split(".")
    if 2 <= len(parts) <= 3 and all(p.isdigit() and len(p) <= _BUILD_NUMBER_COMPONENT_WIDTH for p in parts):
        parts += ["0"] * (3 - len(parts))
        return sum(int(part) * 10 ** (_BUILD_NUMBER_COMPONENT_WIDTH * (2 - i)) for i, part in enumerate(parts))

    return None
