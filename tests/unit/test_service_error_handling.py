"""Test error handling in the LaunchpadService."""

import tempfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from launchpad.service import LaunchpadService


class TestLaunchpadServiceErrorHandling:
    """Test error handling in LaunchpadService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = LaunchpadService()
        self.service._statsd = Mock()
        self.service._service_config = {"sentry_base_url": "http://test.com"}

    def test_handle_kafka_message_unsupported_artifact(self):
        """Test that unsupported artifact errors are handled gracefully."""
        # Create a mock payload
        payload = {
            "artifact_id": "test-artifact",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        # Mock the process_artifact_analysis method to raise ValueError
        with patch.object(
            self.service,
            "process_artifact_analysis",
            side_effect=ValueError("Input is not a supported artifact"),
        ):
            # This should not raise an exception
            self.service.handle_kafka_message(payload)

            # Verify that the correct statsd metric was incremented
            self.service._statsd.increment.assert_called_with(
                "launchpad.artifact.processing.unsupported_type"
            )

    def test_handle_kafka_message_validation_error(self):
        """Test that general validation errors are handled gracefully."""
        payload = {
            "artifact_id": "test-artifact",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        with patch.object(
            self.service,
            "process_artifact_analysis",
            side_effect=ValueError("Some other validation error"),
        ):
            # This should not raise an exception
            self.service.handle_kafka_message(payload)

            # Verify that the correct statsd metric was incremented
            self.service._statsd.increment.assert_called_with(
                "launchpad.artifact.processing.validation_error"
            )

    def test_handle_kafka_message_io_error(self):
        """Test that I/O errors are handled gracefully."""
        payload = {
            "artifact_id": "test-artifact",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        with patch.object(
            self.service,
            "process_artifact_analysis",
            side_effect=FileNotFoundError("File not found"),
        ):
            # This should not raise an exception
            self.service.handle_kafka_message(payload)

            # Verify that the correct statsd metric was incremented
            self.service._statsd.increment.assert_called_with(
                "launchpad.artifact.processing.io_error"
            )

    def test_handle_kafka_message_bad_zip_file(self):
        """Test that bad zip file errors are handled gracefully."""
        payload = {
            "artifact_id": "test-artifact",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        with patch.object(
            self.service,
            "process_artifact_analysis",
            side_effect=zipfile.BadZipFile("Bad zip file"),
        ):
            # This should not raise an exception
            self.service.handle_kafka_message(payload)

            # Verify that the correct statsd metric was incremented
            self.service._statsd.increment.assert_called_with(
                "launchpad.artifact.processing.bad_zip"
            )

    def test_handle_kafka_message_corruption_error(self):
        """Test that corruption errors are handled gracefully."""
        payload = {
            "artifact_id": "test-artifact",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        with patch.object(
            self.service,
            "process_artifact_analysis",
            side_effect=Exception("zip file is corrupt"),
        ):
            # This should not raise an exception
            self.service.handle_kafka_message(payload)

            # Verify that the correct statsd metric was incremented
            self.service._statsd.increment.assert_called_with(
                "launchpad.artifact.processing.corruption_error"
            )

    def test_handle_kafka_message_unexpected_error_reraises(self):
        """Test that unexpected errors are re-raised for DLQ handling."""
        payload = {
            "artifact_id": "test-artifact",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        with patch.object(
            self.service,
            "process_artifact_analysis",
            side_effect=Exception("Unexpected error"),
        ):
            # This should re-raise the exception
            with pytest.raises(Exception, match="Unexpected error"):
                self.service.handle_kafka_message(payload)

            # Verify that the correct statsd metric was incremented
            self.service._statsd.increment.assert_called_with(
                "launchpad.artifact.processing.failed"
            )

    def test_create_unsupported_artifact_file(self):
        """Test that unsupported artifact files are handled correctly."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(b"This is not a valid artifact")
            tmp_path = Path(tmp.name)

        try:
            from launchpad.artifacts.artifact_factory import ArtifactFactory

            with pytest.raises(ValueError, match="Input is not a supported artifact"):
                ArtifactFactory.from_path(tmp_path)
        finally:
            tmp_path.unlink()

    def test_create_empty_zip_file(self):
        """Test that empty zip files are handled correctly."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            # Create an empty zip file
            with zipfile.ZipFile(tmp.name, "w") as zf:
                pass  # Empty zip file
            tmp_path = Path(tmp.name)

        try:
            from launchpad.artifacts.artifact_factory import ArtifactFactory

            with pytest.raises(ValueError, match="Input is not a supported artifact"):
                ArtifactFactory.from_path(tmp_path)
        finally:
            tmp_path.unlink()
