"""Tests for the Launchpad service."""

from __future__ import annotations

import json

from unittest.mock import AsyncMock, Mock

import pytest

from aiohttp.test_utils import AioHTTPTestCase

from launchpad.kafka import LaunchpadMessage
from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService


class TestLaunchpadServer(AioHTTPTestCase):
    """Test cases for LaunchpadServer."""

    async def get_application(self):
        """Create the application for testing."""
        server = LaunchpadServer()
        return await server.create_app()

    async def test_health_check(self):
        """Test the basic health check endpoint."""
        resp = await self.client.request("GET", "/health")
        assert resp.status == 200

        data = await resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "launchpad"
        assert "version" in data

    async def test_ready_check(self):
        """Test the readiness check endpoint."""
        resp = await self.client.request("GET", "/ready")
        assert resp.status == 200

        data = await resp.json()
        assert data["status"] == "ready"
        assert data["service"] == "launchpad"


class TestLaunchpadService:
    """Test cases for LaunchpadService."""

    def test_handle_kafka_message_ios(self):
        """Test handling iOS analysis messages."""
        service = LaunchpadService()

        # Mock the iOS analysis handler
        service._handle_ios_analysis = AsyncMock()

        # Create a mock message
        message = LaunchpadMessage(
            topic="test-topic",
            partition=0,
            offset=1,
            key=b"test-key",
            value=json.dumps({"type": "analyze_apple", "file_path": "/path/to/app.zip"}).encode(),
        )

        # handle_kafka_message is synchronous
        service.handle_kafka_message(message)

        # Note: The actual implementation queues tasks async, so we can't easily verify
        # the handler was called in a unit test without more complex mocking

    def test_handle_kafka_message_android(self):
        """Test handling Android analysis messages."""
        service = LaunchpadService()

        # Mock the Android analysis handler
        service._handle_android_analysis = AsyncMock()

        # Create a mock message
        message = LaunchpadMessage(
            topic="test-topic",
            partition=0,
            offset=1,
            key=b"test-key",
            value=json.dumps({"type": "analyze_android", "file_path": "/path/to/app.apk"}).encode(),
        )

        # handle_kafka_message is synchronous
        service.handle_kafka_message(message)

        # Note: The actual implementation queues tasks async, so we can't easily verify
        # the handler was called in a unit test without more complex mocking

    def test_handle_kafka_message_unknown_type(self):
        """Test handling messages with unknown type."""
        service = LaunchpadService()

        # Create a mock message with unknown type
        message = LaunchpadMessage(
            topic="test-topic",
            partition=0,
            offset=1,
            key=b"test-key",
            value=json.dumps({"type": "unknown_type", "data": "test"}).encode(),
        )

        # This should not raise an exception
        service.handle_kafka_message(message)

    def test_handle_kafka_message_invalid_json(self):
        """Test handling messages with invalid JSON."""
        service = LaunchpadService()

        # Create a mock message with invalid JSON
        message = LaunchpadMessage(topic="test-topic", partition=0, offset=1, key=b"test-key", value=b"invalid json")

        # This should not raise an exception
        service.handle_kafka_message(message)

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test the service health check."""
        service = LaunchpadService()

        # Mock the Kafka consumer
        mock_kafka_consumer = Mock()
        mock_kafka_consumer.health_check = AsyncMock(
            return_value={
                "status": "ok",
                "topics": ["test-topic"],
            }
        )
        service.kafka_consumer = mock_kafka_consumer

        # Mock the server
        service.server = Mock()

        health = await service.health_check()

        assert health["service"] == "launchpad"
        assert health["status"] == "ok"
        assert "components" in health
        assert health["components"]["kafka"]["status"] == "ok"
        assert health["components"]["server"]["status"] == "ok"
