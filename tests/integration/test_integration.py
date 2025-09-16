"""Integration tests for the Launchpad service."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService, ServiceConfig
from launchpad.utils.statsd import FakeStatsd


class TestServiceIntegration:
    """Integration tests for the full service."""

    @pytest.mark.asyncio
    async def test_kafka_message_processing(self):
        """Test processing of different Kafka message types."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        # Mock service config to make the service appear initialized
        service._service_config = ServiceConfig(
            sentry_base_url="https://sentry.example.com",
            projects_to_skip=[],
        )

        # Mock process_artifact to avoid actual processing
        with patch.object(service, "process_artifact") as mock_process:
            # Test artifact analysis message with iOS artifact
            ios_payload: PreprodArtifactEvents = {
                "artifact_id": "ios-test-123",
                "project_id": "test-project-ios",
                "organization_id": "test-org-123",
            }

            # handle_kafka_message is synchronous
            service.handle_kafka_message(ios_payload)

            # Verify the processing method was called
            mock_process.assert_called_once_with("ios-test-123", "test-project-ios", "test-org-123")

            # Verify statsd metrics were sent
            calls = fake_statsd.calls
            assert ("increment", {"metric": "artifact.processing.started", "value": 1, "tags": None}) in calls
            assert ("increment", {"metric": "artifact.processing.completed", "value": 1, "tags": None}) in calls

            # Reset mocks for next test
            mock_process.reset_mock()
            fake_statsd.calls.clear()

            # Test artifact analysis message with Android artifact
            android_payload: PreprodArtifactEvents = {
                "artifact_id": "android-test-456",
                "project_id": "test-project-android",
                "organization_id": "test-org-456",
            }

            # handle_kafka_message is synchronous
            service.handle_kafka_message(android_payload)

            # Verify the processing method was called
            mock_process.assert_called_once_with("android-test-456", "test-project-android", "test-org-456")

    @pytest.mark.asyncio
    async def test_error_handling_in_message_processing(self):
        """Test that errors in message processing are handled properly."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        # Create a valid payload
        payload: PreprodArtifactEvents = {
            "artifact_id": "test-123",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        # Mock process_artifact to raise an exception
        with patch.object(service, "process_artifact") as mock_process:
            mock_process.side_effect = Exception("Processing failed")

            # This should handle the exception gracefully
            service.handle_kafka_message(payload)

            # Verify the processing method was called
            mock_process.assert_called_once_with("test-123", "test-project", "test-org")

            # Verify statsd metrics were sent including failure metric
            calls = fake_statsd.calls
            increment_calls = [call for call in calls if call[0] == "increment"]
            assert len(increment_calls) == 2  # started and failed
            assert increment_calls[0][1]["metric"] == "artifact.processing.started"
            assert increment_calls[1][1]["metric"] == "artifact.processing.failed"

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that multiple messages can be processed concurrently."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        messages = [
            {
                "artifact_id": f"test-artifact-{i}",
                "project_id": f"test-project-{i}",
                "organization_id": f"test-org-{i}",
            }
            for i in range(10)
        ]

        with patch.object(service, "process_artifact"):
            for msg in messages:
                service.handle_kafka_message(msg)  # type: ignore

        # Verify all messages were processed (2 increment calls per message: started + completed)
        calls = fake_statsd.calls
        increment_calls = [call for call in calls if call[0] == "increment"]
        assert len(increment_calls) == 20


@pytest.mark.integration
class TestServiceWithMockServer:
    """Integration tests that actually start the HTTP server."""

    @pytest.mark.asyncio
    async def test_http_endpoints_while_service_running(self):
        """Test HTTP endpoints while the service is running (mocked)."""
        # This is a placeholder for a more complex integration test
        # that would start the actual service and test HTTP endpoints
        # For now, we test the components separately

        fake_statsd = FakeStatsd()
        server = LaunchpadServer(lambda: True, host="127.0.0.1", port=0, statsd=fake_statsd)  # Random port
        app = server.create_app()

        # Test that we can create the app without errors
        assert app is not None

        # In a real integration test, we would:
        # 1. Start the service in a background task
        # 2. Make HTTP requests to test endpoints
        # 3. Send Kafka messages to test processing
        # 4. Verify end-to-end behavior

        # For now, this validates the service structure is correct
