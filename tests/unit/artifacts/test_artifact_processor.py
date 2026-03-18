from unittest.mock import Mock, patch

from objectstore_client import Client as ObjectstoreClient

from launchpad.artifact_processor import ArtifactProcessor
from launchpad.constants import (
    ProcessingErrorCode,
    ProcessingErrorMessage,
)
from launchpad.sentry_client import SentryClient, SentryClientError
from launchpad.service import ObjectstoreConfig, ServiceConfig
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
