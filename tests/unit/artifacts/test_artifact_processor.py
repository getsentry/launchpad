from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from objectstore_client import Client as ObjectstoreClient
from taskbroker_client.worker.workerchild import ProcessingDeadlineExceeded

from launchpad.artifact_processor import ArtifactProcessor, ServiceConfig, _parse_build_number
from launchpad.artifacts.android.aab import AAB
from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.artifacts.artifact import Artifact
from launchpad.constants import (
    InstallableAppErrorCode,
    ProcessingErrorCode,
    ProcessingErrorMessage,
)
from launchpad.sentry_client import SentryClient, SentryClientError
from launchpad.size.models.android import AndroidAppInfo
from launchpad.utils.objectstore import ObjectstoreConfig
from launchpad.utils.statsd import FakeStatsd


class TestArtifactProcessorErrorHandling:
    def setup_method(self):
        """Set up test fixtures."""
        mock_sentry_client = Mock(spec=SentryClient)
        mock_statsd = Mock()
        mock_objectstore_client = Mock(spec=ObjectstoreClient)
        self.processor = ArtifactProcessor(mock_sentry_client, mock_statsd, mock_objectstore_client)

    def test_update_artifact_error_success(self):
        """Test that _update_artifact_error successfully updates artifact with error."""
        mock_sentry_client = Mock()
        mock_sentry_client.update_artifact.return_value = None
        self.processor._sentry_client = mock_sentry_client

        self.processor._update_artifact_error(
            "test-org-id",
            "test-project-id",
            "test-artifact-id",
            ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
            ProcessingErrorMessage.PREPROCESSING_FAILED,
        )

        mock_sentry_client.update_artifact.assert_called_once_with(
            org="test-org-id",
            project="test-project-id",
            artifact_id="test-artifact-id",
            data={
                "error_code": ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR.value,
                "error_message": ProcessingErrorMessage.PREPROCESSING_FAILED.value,
            },
        )

    def test_update_artifact_error_failure(self):
        """Test that _update_artifact_error handles update failures gracefully."""
        mock_sentry_client = Mock()
        mock_sentry_client.update_artifact.return_value = {"error": "Update failed"}
        self.processor._sentry_client = mock_sentry_client

        # Should not raise an exception
        self.processor._update_artifact_error(
            "test-org-id",
            "test-project-id",
            "test-artifact-id",
            ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
            ProcessingErrorMessage.PREPROCESSING_FAILED,
        )

        mock_sentry_client.update_artifact.assert_called_once()

    def test_update_artifact_error_exception(self):
        """Test that _update_artifact_error handles exceptions gracefully."""
        mock_sentry_client = Mock()
        mock_sentry_client.update_artifact.side_effect = SentryClientError()
        self.processor._sentry_client = mock_sentry_client

        # Should not raise an exception
        self.processor._update_artifact_error(
            "test-org-id",
            "test-project-id",
            "test-artifact-id",
            ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
            ProcessingErrorMessage.PREPROCESSING_FAILED,
        )

        mock_sentry_client.update_artifact.assert_called_once()

    def test_update_artifact_error_with_detailed_message(self):
        """Test that _update_artifact_error uses detailed error message when provided."""
        mock_statsd = Mock()
        self.processor._statsd = mock_statsd

        mock_client = Mock()
        mock_client.update_artifact.return_value = {"success": True}
        self.processor._sentry_client = mock_client

        detailed_error = "Failed to parse Info.plist: [Errno 2] No such file or directory"

        self.processor._update_artifact_error(
            "test_org_id",
            "test_project_id",
            "test_artifact_id",
            ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
            ProcessingErrorMessage.PREPROCESSING_FAILED,
            detailed_error,
        )

        # Verify that the detailed error message is used instead of the enum value
        expected_error_message = f"{ProcessingErrorMessage.PREPROCESSING_FAILED.value}: {detailed_error}"
        mock_client.update_artifact.assert_called_once_with(
            org="test_org_id",
            project="test_project_id",
            artifact_id="test_artifact_id",
            data={
                "error_code": ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR.value,
                "error_message": expected_error_message,
            },
        )

        # Verify datadog logging
        mock_statsd.increment.assert_called_once_with(
            "artifact.processing.error",
            tags=[
                "error_code:3",
                "error_type:PREPROCESSING_FAILED",
                "project_id:test_project_id",
                "organization_id:test_org_id",
            ],
        )

    def test_processing_error_message_enum_values(self):
        """Test that ProcessingErrorMessage enum has expected values."""
        # Test that all enum values are strings
        for error_message in ProcessingErrorMessage:
            assert isinstance(error_message.value, str)
            assert len(error_message.value) > 0

        # Test some specific values
        assert ProcessingErrorMessage.DOWNLOAD_FAILED.value == "Failed to download artifact from Sentry"
        assert ProcessingErrorMessage.PREPROCESSING_FAILED.value == "Failed to extract basic app information"
        assert ProcessingErrorMessage.SIZE_ANALYSIS_FAILED.value == "Failed to perform size analysis"
        assert ProcessingErrorMessage.UNKNOWN_ERROR.value == "An unknown error occurred"

    def test_do_distribution_unknown_artifact_type_reports_error(self):
        mock_sentry_client = Mock(spec=SentryClient)
        mock_sentry_client.update_distribution.return_value = None
        mock_statsd = Mock()
        self.processor._sentry_client = mock_sentry_client
        self.processor._statsd = mock_statsd

        unknown_artifact = Mock(spec=Artifact)
        mock_info = Mock()

        self.processor._do_distribution(
            "test-org-id", "test-project-id", "test-artifact-id", unknown_artifact, mock_info
        )

        mock_sentry_client.update_distribution.assert_called_once_with(
            org="test-org-id",
            artifact_id="test-artifact-id",
            data={
                "error_code": InstallableAppErrorCode.UNSUPPORTED_ARTIFACT_TYPE.value,
                "error_message": "This artifact type is not supported for distribution.",
            },
        )
        mock_statsd.increment.assert_called_once_with(
            "distribution.processing.error",
            tags=[
                f"error_code:{InstallableAppErrorCode.UNSUPPORTED_ARTIFACT_TYPE.value}",
                "organization_id:test-org-id",
            ],
        )

    def test_do_distribution_invalid_code_signature_reports_skip(self):
        mock_sentry_client = Mock(spec=SentryClient)
        mock_sentry_client.update_distribution.return_value = None
        mock_statsd = Mock()
        self.processor._sentry_client = mock_sentry_client
        self.processor._statsd = mock_statsd

        artifact = Mock(spec=ZippedXCArchive)
        mock_info = Mock()
        mock_info.is_code_signature_valid = False
        mock_info.is_simulator = False

        self.processor._do_distribution("test-org-id", "test-project-id", "test-artifact-id", artifact, mock_info)

        mock_sentry_client.update_distribution.assert_called_once_with(
            org="test-org-id",
            artifact_id="test-artifact-id",
            data={
                "error_code": InstallableAppErrorCode.INVALID_CODE_SIGNATURE.value,
                "error_message": "The build's code signature could not be verified.",
            },
        )
        mock_statsd.increment.assert_called_once_with(
            "distribution.processing.error",
            tags=[
                f"error_code:{InstallableAppErrorCode.INVALID_CODE_SIGNATURE.value}",
                "organization_id:test-org-id",
            ],
        )
        mock_sentry_client.upload_installable_app.assert_not_called()

    def test_do_distribution_simulator_build_reports_skip(self):
        mock_sentry_client = Mock(spec=SentryClient)
        mock_sentry_client.update_distribution.return_value = None
        mock_statsd = Mock()
        self.processor._sentry_client = mock_sentry_client
        self.processor._statsd = mock_statsd

        artifact = Mock(spec=ZippedXCArchive)
        mock_info = Mock()
        mock_info.is_code_signature_valid = True
        mock_info.is_simulator = True

        self.processor._do_distribution("test-org-id", "test-project-id", "test-artifact-id", artifact, mock_info)

        mock_sentry_client.update_distribution.assert_called_once_with(
            org="test-org-id",
            artifact_id="test-artifact-id",
            data={
                "error_code": InstallableAppErrorCode.SIMULATOR_BUILD.value,
                "error_message": "Simulator builds cannot be distributed.",
            },
        )
        mock_statsd.increment.assert_called_once_with(
            "distribution.processing.error",
            tags=[
                f"error_code:{InstallableAppErrorCode.SIMULATOR_BUILD.value}",
                "organization_id:test-org-id",
            ],
        )
        mock_sentry_client.upload_installable_app.assert_not_called()


class TestArtifactProcessorMessageHandling:
    """Test message processing functionality in ArtifactProcessor."""

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_ios(self, mock_process, mock_sentry_client):
        """Test processing iOS artifact messages."""
        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

        ArtifactProcessor.process_message(
            artifact_id="ios-test-123",
            project_id="test-project-ios",
            organization_id="test-org-123",
            service_config=service_config,
            statsd=fake_statsd,
        )

        mock_process.assert_called_once_with(
            "test-org-123",
            "test-project-ios",
            "ios-test-123",
        )

        # Verify metrics were recorded
        calls = fake_statsd.calls
        assert (
            "increment",
            {"metric": "artifact.processing.started", "value": 1, "tags": None},
        ) in calls
        assert (
            "increment",
            {"metric": "artifact.processing.completed", "value": 1, "tags": None},
        ) in calls

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_android(self, mock_process, mock_sentry_client):
        """Test processing Android artifact messages."""
        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

        ArtifactProcessor.process_message(
            artifact_id="android-test-456",
            project_id="test-project-android",
            organization_id="test-org-456",
            service_config=service_config,
            statsd=fake_statsd,
        )

        mock_process.assert_called_once_with(
            "test-org-456",
            "test-project-android",
            "android-test-456",
        )

        # Verify metrics were recorded
        calls = fake_statsd.calls
        assert (
            "increment",
            {"metric": "artifact.processing.started", "value": 1, "tags": None},
        ) in calls
        assert (
            "increment",
            {"metric": "artifact.processing.completed", "value": 1, "tags": None},
        ) in calls

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_error(self, mock_process, mock_sentry_client):
        """Test error handling in message processing."""
        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

        mock_process.side_effect = RuntimeError("Download failed: HTTP 404")

        ArtifactProcessor.process_message(
            artifact_id="test-123",
            project_id="test-project",
            organization_id="test-org",
            service_config=service_config,
            statsd=fake_statsd,
        )

        mock_process.assert_called_once_with(
            "test-org",
            "test-project",
            "test-123",
        )

        # Verify the metrics were called correctly
        calls = fake_statsd.calls
        increment_calls = [call for call in calls if call[0] == "increment"]
        assert len(increment_calls) == 2
        assert increment_calls[0][1]["metric"] == "artifact.processing.started"
        assert increment_calls[1][1]["metric"] == "artifact.processing.failed"

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_project_skipped(self, mock_process, mock_sentry_client):
        """Test that projects in the skip list are not processed."""
        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=["skip-project-1", "skip-project-2"],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

        ArtifactProcessor.process_message(
            artifact_id="skip-test-123",
            project_id="skip-project-1",
            organization_id="test-org-123",
            service_config=service_config,
            statsd=fake_statsd,
        )

        mock_process.assert_not_called()

        calls = fake_statsd.calls
        assert len(calls) == 0

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_project_not_skipped(self, mock_process, mock_sentry_client):
        """Test that projects not in the skip list are processed normally."""
        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=["other-project"],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

        ArtifactProcessor.process_message(
            artifact_id="normal-test-123",
            project_id="normal-project",
            organization_id="test-org-123",
            service_config=service_config,
            statsd=fake_statsd,
        )

        mock_process.assert_called_once_with(
            "test-org-123",
            "normal-project",
            "normal-test-123",
        )

        # Verify normal metrics were recorded
        calls = fake_statsd.calls
        assert (
            "increment",
            {"metric": "artifact.processing.started", "value": 1, "tags": None},
        ) in calls
        assert (
            "increment",
            {"metric": "artifact.processing.completed", "value": 1, "tags": None},
        ) in calls

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_duration_includes_org_slug(self, mock_process, mock_sentry_client):
        """The processing duration metric is tagged with organization_slug when provided."""
        mock_process.return_value = "xcarchive"
        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

        ArtifactProcessor.process_message(
            artifact_id="slug-test-123",
            project_id="test-project",
            organization_id="test-org-123",
            organization_slug="acme-inc",
            service_config=service_config,
            statsd=fake_statsd,
        )

        timing = next(
            c[1] for c in fake_statsd.calls if c[0] == "timing" and c[1]["metric"] == "artifact.processing.duration"
        )
        assert "organization_slug:acme-inc" in timing["tags"]
        assert "organization_id:test-org-123" in timing["tags"]

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_duration_omits_slug_when_absent(self, mock_process, mock_sentry_client):
        """No organization_slug tag is emitted when the slug is not provided (rollout compatibility)."""
        mock_process.return_value = "xcarchive"
        fake_statsd = FakeStatsd()
        service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

        ArtifactProcessor.process_message(
            artifact_id="no-slug-123",
            project_id="test-project",
            organization_id="test-org-123",
            service_config=service_config,
            statsd=fake_statsd,
        )

        timing = next(
            c[1] for c in fake_statsd.calls if c[0] == "timing" and c[1]["metric"] == "artifact.processing.duration"
        )
        assert not any(tag.startswith("organization_slug:") for tag in timing["tags"])

    @staticmethod
    def _duration_tags(fake_statsd):
        timing = next(
            c[1] for c in fake_statsd.calls if c[0] == "timing" and c[1]["metric"] == "artifact.processing.duration"
        )
        return timing["tags"]

    @staticmethod
    def _service_config():
        return ServiceConfig(
            sentry_base_url="http://test.sentry.io",
            projects_to_skip=[],
            objectstore_config=ObjectstoreConfig(objectstore_url="http://test.objectstore.io"),
        )

    @pytest.mark.parametrize(
        "artifact_type,expected_platform",
        [("xcarchive", "ios"), ("aab", "android"), ("apk", "android"), ("unknown", "unknown")],
    )
    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_platform_on_success(
        self, mock_process, mock_sentry_client, artifact_type, expected_platform
    ):
        """Successful builds map artifact_type to a platform tag (aab/apk both -> android)."""
        mock_process.return_value = artifact_type
        fake_statsd = FakeStatsd()

        ArtifactProcessor.process_message(
            artifact_id="a",
            project_id="p",
            organization_id="o",
            service_config=self._service_config(),
            statsd=fake_statsd,
        )

        assert f"platform:{expected_platform}" in self._duration_tags(fake_statsd)

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_platform_timeout(self, mock_process, mock_sentry_client):
        """Builds that exceed the processing deadline are tagged platform:timeout."""
        mock_process.side_effect = ProcessingDeadlineExceeded()
        fake_statsd = FakeStatsd()

        with pytest.raises(ProcessingDeadlineExceeded):
            ArtifactProcessor.process_message(
                artifact_id="a",
                project_id="p",
                organization_id="o",
                service_config=self._service_config(),
                statsd=fake_statsd,
            )

        assert "platform:timeout" in self._duration_tags(fake_statsd)

    @patch("launchpad.artifact_processor.SentryClient")
    @patch.object(ArtifactProcessor, "process_artifact")
    def test_process_message_platform_failed(self, mock_process, mock_sentry_client):
        """Builds that fail before type detection are tagged platform:failed."""
        mock_process.side_effect = RuntimeError("boom")
        fake_statsd = FakeStatsd()

        ArtifactProcessor.process_message(
            artifact_id="a",
            project_id="p",
            organization_id="o",
            service_config=self._service_config(),
            statsd=fake_statsd,
        )

        assert "platform:failed" in self._duration_tags(fake_statsd)


class TestParseBuildNumber:
    @pytest.mark.parametrize(
        "build,expected",
        [
            # Plain integers (e.g. Android versionCode) pass through unchanged
            ("9999", 9999),
            ("0", 0),
            ("1", 1),
            # Apple CFBundleVersion: two or three dot-separated non-negative integers
            ("1.2.3", 1_000_002_000_003),
            ("1.2", 1_000_002_000_000),
            # CFBundleVersion allows more than three groups; groups beyond the
            # third are dropped
            ("1.2.3.4", 1_000_002_000_003),
            ("1.2.3.4.5", 1_000_002_000_003),
            ("1.2.3.0", 1_000_002_000_003),
            # Dropped groups are not width-checked, but must still be numeric
            ("1.2.3.1234567", 1_000_002_000_003),
            ("1.2.3.beta", None),
            ("1.2.3.", None),
            # Malformed or unsupported shapes fall back to None, same as before
            ("1.2.a", None),
            ("abc", None),
            ("", None),
            # A component too wide for the padding width is refused rather than
            # silently corrupting the ordering of adjacent components
            ("1234567.2.3", None),
        ],
    )
    def test_parse_build_number(self, build, expected):
        assert _parse_build_number(build) == expected

    def test_dotted_builds_sort_correctly_within_a_version(self):
        # Naive "strip the dots and parse as one number" concatenation would rank
        # 1.99 ("199") above 2.0 ("20"), even though 1.99 is the earlier build.
        assert _parse_build_number("1.99") < _parse_build_number("2.0")

    def test_distinguishes_builds_that_naive_concatenation_would_collide(self):
        # "1.2.3", "12.3", and "1.23" would all naively concatenate to "123".
        assert _parse_build_number("1.2.3") != _parse_build_number("12.3")
        assert _parse_build_number("1.2.3") != _parse_build_number("1.23")


class TestPrepareUpdateData:
    def setup_method(self):
        """Set up test fixtures."""
        mock_sentry_client = Mock(spec=SentryClient)
        mock_statsd = Mock()
        mock_objectstore_client = Mock(spec=ObjectstoreClient)
        self.processor = ArtifactProcessor(mock_sentry_client, mock_statsd, mock_objectstore_client)

    def test_dotted_build_number_is_parsed_and_raw_value_preserved(self):
        app_info = AndroidAppInfo(
            name="My App",
            version="1.2.300",
            build="1.2.3",
            app_id="com.example.app",
            has_proguard_mapping=False,
        )

        update_data = self.processor._prepare_update_data(
            app_info=app_info,
            artifact=Mock(spec=AAB),
            dequeued_at=datetime(2026, 1, 1),
            app_icon_id=None,
        )

        assert update_data["build_number"] == 1_000_002_000_003
        assert update_data["build_number_raw"] == "1.2.3"

    def test_plain_build_number_still_parses_as_int(self):
        app_info = AndroidAppInfo(
            name="My App",
            version="1.2.300",
            build="9999",
            app_id="com.example.app",
            has_proguard_mapping=False,
        )

        update_data = self.processor._prepare_update_data(
            app_info=app_info,
            artifact=Mock(spec=AAB),
            dequeued_at=datetime(2026, 1, 1),
            app_icon_id=None,
        )

        assert update_data["build_number"] == 9999
        assert update_data["build_number_raw"] == "9999"
