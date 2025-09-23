"""Tests for error handling and retry logic in LaunchpadService."""

from unittest.mock import Mock

import pytest

from launchpad.constants import (
    MAX_RETRY_ATTEMPTS,
    OperationName,
    ProcessingErrorCode,
    ProcessingErrorMessage,
)
from launchpad.sentry_client import SentryClientError
from launchpad.service import LaunchpadService


class TestLaunchpadServiceErrorHandling:
    """Test error handling and retry logic in LaunchpadService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = LaunchpadService()
        self.service._service_config = {
            "sentry_base_url": "https://test.sentry.io",
            "statsd_host": "localhost",
            "statsd_port": 8125,
        }
        self.service._statsd = Mock()

    def test_retry_operation_success_on_first_attempt(self):
        """Test that _retry_operation succeeds on first attempt."""
        operation = Mock(return_value="success")

        result = self.service._retry_operation(
            operation,
            OperationName.PREPROCESSING,
        )

        assert result == "success"
        assert operation.call_count == 1

    def test_retry_operation_success_on_second_attempt(self):
        """Test that _retry_operation succeeds on second attempt after one failure."""
        operation = Mock()
        operation.side_effect = [RuntimeError("Temporary failure"), "success"]

        result = self.service._retry_operation(
            operation,
            OperationName.PREPROCESSING,
        )

        assert result == "success"
        assert operation.call_count == 2

    def test_retry_operation_fails_after_max_attempts(self):
        """Test that _retry_operation fails after MAX_RETRY_ATTEMPTS."""
        operation = Mock()
        operation.side_effect = RuntimeError("Persistent failure")

        with pytest.raises(RuntimeError, match="Failed to extract basic app information"):
            self.service._retry_operation(
                operation,
                OperationName.PREPROCESSING,
            )

        assert operation.call_count == MAX_RETRY_ATTEMPTS

    def test_retry_operation_non_retryable_error(self):
        """Test that _retry_operation doesn't retry non-retryable errors."""
        operation = Mock()
        operation.side_effect = ValueError("Invalid input")

        with pytest.raises(RuntimeError, match="Failed to perform size analysis"):
            self.service._retry_operation(
                operation,
                OperationName.SIZE_ANALYSIS,
            )

        assert operation.call_count == 1  # Should not retry

    def test_retry_operation_maps_operation_to_correct_error_message(self):
        """Test that _retry_operation correctly maps operation names to error messages."""
        operation = Mock()
        operation.side_effect = RuntimeError("Persistent failure")

        # Test PREPROCESSING maps to PREPROCESSING_FAILED
        with pytest.raises(RuntimeError, match="Failed to extract basic app information"):
            self.service._retry_operation(operation, OperationName.PREPROCESSING)

        # Test SIZE_ANALYSIS maps to SIZE_ANALYSIS_FAILED
        with pytest.raises(RuntimeError, match="Failed to perform size analysis"):
            self.service._retry_operation(operation, OperationName.SIZE_ANALYSIS)

    def test_update_artifact_error_success(self):
        """Test that _update_artifact_error successfully updates artifact with error."""
        mock_sentry_client = Mock()
        mock_sentry_client.update_artifact.return_value = None
        self.service._sentry_client = mock_sentry_client

        self.service._update_artifact_error(
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
        self.service._sentry_client = mock_sentry_client

        # Should not raise an exception
        self.service._update_artifact_error(
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
        self.service._sentry_client = mock_sentry_client

        # Should not raise an exception
        self.service._update_artifact_error(
            "test-org-id",
            "test-project-id",
            "test-artifact-id",
            ProcessingErrorCode.ARTIFACT_PROCESSING_ERROR,
            ProcessingErrorMessage.PREPROCESSING_FAILED,
        )

        mock_sentry_client.update_artifact.assert_called_once()

    def test_update_artifact_error_with_detailed_message(self):
        """Test that _update_artifact_error uses detailed error message when provided."""
        self.service._statsd = Mock()

        mock_client = Mock()
        mock_client.update_artifact.return_value = {"success": True}
        self.service._sentry_client = mock_client

        detailed_error = "Failed to parse Info.plist: [Errno 2] No such file or directory"

        self.service._update_artifact_error(
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
        self.service._statsd.increment.assert_called_once_with(
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
