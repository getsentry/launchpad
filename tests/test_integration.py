"""Integration tests for the Launchpad service."""

from __future__ import annotations

import asyncio
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

        # Test iOS analysis message
        ios_message = LaunchpadMessage(
            topic="launchpad-events",
            partition=0,
            offset=1,
            key=b"ios-analysis",
            value=json.dumps(
                {"type": "analyze_ios", "file_path": "/path/to/app.xcarchive.zip", "metadata": {"version": "1.0.0"}}
            ).encode(),
        )

        # Mock the analysis handler
        service._handle_ios_analysis = AsyncMock()

        await service.handle_kafka_message(ios_message)

        # Verify the handler was called with correct payload
        service._handle_ios_analysis.assert_called_once_with(
            {"type": "analyze_ios", "file_path": "/path/to/app.xcarchive.zip", "metadata": {"version": "1.0.0"}}
        )

        # Test Android analysis message
        android_message = LaunchpadMessage(
            topic="launchpad-events",
            partition=0,
            offset=2,
            key=b"android-analysis",
            value=json.dumps(
                {"type": "analyze_android", "file_path": "/path/to/app.apk", "metadata": {"version": "2.0.0"}}
            ).encode(),
        )

        # Mock the analysis handler
        service._handle_android_analysis = AsyncMock()

        await service.handle_kafka_message(android_message)

        # Verify the handler was called with correct payload
        service._handle_android_analysis.assert_called_once_with(
            {"type": "analyze_android", "file_path": "/path/to/app.apk", "metadata": {"version": "2.0.0"}}
        )

    @pytest.mark.asyncio
    async def test_error_handling_in_message_processing(self):
        """Test that errors in message processing don't crash the service."""
        service = LaunchpadService()

        # Test with malformed JSON
        bad_message = LaunchpadMessage(
            topic="launchpad-events", partition=0, offset=1, key=b"bad-message", value=b"not json"
        )

        # This should not raise an exception
        await service.handle_kafka_message(bad_message)

        # Test with missing required fields
        incomplete_message = LaunchpadMessage(
            topic="launchpad-events",
            partition=0,
            offset=2,
            key=b"incomplete",
            value=json.dumps({"data": "missing type field"}).encode(),
        )

        # This should not raise an exception
        await service.handle_kafka_message(incomplete_message)

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that multiple messages can be processed concurrently."""
        service = LaunchpadService()

        # Mock analysis handlers
        service._handle_ios_analysis = AsyncMock()
        service._handle_android_analysis = AsyncMock()

        # Create multiple messages
        messages = [
            LaunchpadMessage(
                topic="launchpad-events",
                partition=0,
                offset=i,
                key=f"message-{i}".encode(),
                value=json.dumps(
                    {
                        "type": "analyze_ios" if i % 2 == 0 else "analyze_android",
                        "file_path": f"/path/to/app{i}.zip",
                    }
                ).encode(),
            )
            for i in range(10)
        ]

        # Process all messages concurrently
        tasks = [service.handle_kafka_message(msg) for msg in messages]
        await asyncio.gather(*tasks)

        # Verify handlers were called the expected number of times
        assert service._handle_ios_analysis.call_count == 5  # Even indices
        assert service._handle_android_analysis.call_count == 5  # Odd indices


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
