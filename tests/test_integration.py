"""Integration tests for the Launchpad service."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from launchpad.kafka import LaunchpadMessage
from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService


class TestServiceIntegration:
    """Integration tests for the full service."""

    @pytest.mark.asyncio
    async def test_service_startup_and_health(self):
        """Test that the service can start up and respond to health checks."""
        service = LaunchpadService()

        # Mock the Kafka consumer to avoid needing actual Kafka
        service.kafka_consumer = AsyncMock()
        service.kafka_consumer.start = AsyncMock()
        service.kafka_consumer.stop = AsyncMock()
        service.kafka_consumer.health_check = AsyncMock(
            return_value={
                "status": "ok",
                "topics": ["test-topic"],
            }
        )

        await service.setup()

        # Test health check before starting
        health = await service.health_check()
        assert health["service"] == "launchpad"
        assert health["status"] == "ok"

    @pytest.mark.asyncio
    async def test_kafka_message_processing(self):
        """Test processing of different Kafka message types."""
        service = LaunchpadService()

        # Test artifact analysis message with Apple artifact
        ios_message = LaunchpadMessage(
            topic="launchpad-events",
            partition=0,
            offset=1,
            key=b"ios-analysis",
            value=json.dumps(
                {
                    "type": "analyze_artifact",
                    "artifact_id": "ios-test-123",
                    "artifact_path": "/path/to/app.xcarchive.zip",
                    "metadata": {"version": "1.0.0"},
                }
            ).encode(),
        )

        # handle_kafka_message is synchronous - it queues async work
        service.handle_kafka_message(ios_message)

        # Test artifact analysis message with Android artifact
        android_message = LaunchpadMessage(
            topic="launchpad-events",
            partition=0,
            offset=2,
            key=b"android-analysis",
            value=json.dumps(
                {
                    "type": "analyze_artifact",
                    "artifact_id": "android-test-456",
                    "artifact_path": "/path/to/app.apk",
                    "metadata": {"version": "2.0.0"},
                }
            ).encode(),
        )

        # handle_kafka_message is synchronous - it queues async work
        service.handle_kafka_message(android_message)

        # Note: The actual implementation queues tasks async, so we can't easily verify
        # the handlers were called in a unit test without more complex mocking

    @pytest.mark.asyncio
    async def test_error_handling_in_message_processing(self):
        """Test that errors in message processing don't crash the service."""
        service = LaunchpadService()

        # Test with malformed JSON
        bad_message = LaunchpadMessage(
            topic="launchpad-events", partition=0, offset=1, key=b"bad-message", value=b"not json"
        )

        # This should not raise an exception
        service.handle_kafka_message(bad_message)

        # Test with missing required fields
        incomplete_message = LaunchpadMessage(
            topic="launchpad-events",
            partition=0,
            offset=2,
            key=b"incomplete",
            value=json.dumps({"data": "missing type field"}).encode(),
        )

        # This should not raise an exception
        service.handle_kafka_message(incomplete_message)

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that multiple messages can be processed concurrently."""
        service = LaunchpadService()

        # Mock analysis handler
        service._handle_analysis_async = AsyncMock()

        # Create multiple messages with different artifact types
        messages = [
            LaunchpadMessage(
                topic="launchpad-events",
                partition=0,
                offset=i,
                key=f"message-{i}".encode(),
                value=json.dumps(
                    {
                        "type": "analyze_artifact",
                        "artifact_id": f"test-artifact-{i}",
                        "artifact_path": f"/path/to/app{i}.{'xcarchive.zip' if i % 2 == 0 else 'apk'}",
                    }
                ).encode(),
            )
            for i in range(10)
        ]

        # Process all messages (handle_kafka_message is synchronous)
        for msg in messages:
            service.handle_kafka_message(msg)

        # Note: The actual implementation queues tasks async, so we can't easily verify
        # handler call counts in a unit test without more complex mocking


@pytest.mark.integration
class TestServiceWithMockServer:
    """Integration tests that actually start the HTTP server."""

    @pytest.mark.asyncio
    async def test_http_endpoints_while_service_running(self):
        """Test HTTP endpoints while the service is running (mocked version)."""
        # This is a placeholder for a more complex integration test
        # that would start the actual service and test HTTP endpoints
        # For now, we test the components separately

        server = LaunchpadServer(host="127.0.0.1", port=0)  # Use port 0 for random port
        app = await server.create_app()

        # Test that we can create the app without errors
        assert app is not None

        # In a real integration test, we would:
        # 1. Start the service in a background task
        # 2. Make HTTP requests to test endpoints
        # 3. Send Kafka messages to test processing
        # 4. Verify end-to-end behavior

        # For now, this validates the service structure is correct
