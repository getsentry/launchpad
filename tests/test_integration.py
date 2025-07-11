"""Integration tests for the Launchpad service."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService


class TestServiceIntegration:
    """Integration tests for the full service."""

    @pytest.mark.asyncio
    async def test_service_startup_and_health(self, tmp_path):
        """Test that the service can start up and respond to health checks."""
        # Create a temporary healthcheck file
        healthcheck_file = tmp_path / "healthcheck"
        healthcheck_file.touch()

        with patch.dict("os.environ", {"KAFKA_HEALTHCHECK_FILE": str(healthcheck_file)}):
            service = LaunchpadService()

            # Mock the Kafka processor to avoid needing actual Kafka
            service.kafka_processor = Mock()
            service._healthcheck_file = str(healthcheck_file)

            await service.setup()

            # Test health check
            health = await service.health_check()
            assert health["service"] == "launchpad"
            assert health["status"] == "ok"
            assert "kafka" in health["components"]

    @pytest.mark.asyncio
    async def test_kafka_message_processing(self):
        """Test processing of different Kafka message types."""
        service = LaunchpadService()

        # Mock statsd
        service._statsd = Mock()

        # Mock service config to make the service appear initialized
        service._service_config = {
            "statsd_host": "127.0.0.1",
            "statsd_port": 8125,
            "sentry_base_url": "https://sentry.example.com",
        }

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
            service._statsd.increment.assert_any_call("launchpad.artifact.processing.started")
            service._statsd.increment.assert_any_call("launchpad.artifact.processing.completed")

            # Reset mocks for next test
            mock_process.reset_mock()
            service._statsd.reset_mock()

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
        service = LaunchpadService()

        # Mock statsd
        service._statsd = Mock()

        # Create a valid payload
        payload: PreprodArtifactEvents = {
            "artifact_id": "test-123",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        # Mock the handler to raise an exception
        with patch.object(service, "_statsd") as mock_statsd:
            mock_statsd.increment.side_effect = [
                None,  # First call: processing.started
                Exception("Processing failed"),  # Second call: processing.completed (raises)
                None,  # Third call: processing.failed
            ]

            # This should raise the exception (to be handled by Arroyo)
            with pytest.raises(Exception, match="Processing failed"):
                service.handle_kafka_message(payload)

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that multiple messages can be processed concurrently."""
        service = LaunchpadService()

        # Mock statsd
        service._statsd = Mock()

        # Create multiple messages
        messages = [
            {
                "artifact_id": f"test-artifact-{i}",
                "project_id": f"test-project-{i}",
                "organization_id": f"test-org-{i}",
            }
            for i in range(10)
        ]

        # Process all messages
        for msg in messages:
            service.handle_kafka_message(msg)  # type: ignore

        # Verify all messages were processed
        assert service._statsd.increment.call_count == 20  # 2 calls per message


@pytest.mark.integration
class TestServiceWithMockServer:
    """Integration tests that actually start the HTTP server."""

    @pytest.mark.asyncio
    async def test_http_endpoints_while_service_running(self):
        """Test HTTP endpoints while the service is running (mocked)."""
        # This is a placeholder for a more complex integration test
        # that would start the actual service and test HTTP endpoints
        # For now, we test the components separately

        server = LaunchpadServer(host="127.0.0.1", port=0)  # Random port
        app = await server.create_app()

        # Test that we can create the app without errors
        assert app is not None

        # In a real integration test, we would:
        # 1. Start the service in a background task
        # 2. Make HTTP requests to test endpoints
        # 3. Send Kafka messages to test processing
        # 4. Verify end-to-end behavior

        # For now, this validates the service structure is correct
