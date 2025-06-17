"""Tests for the Launchpad service."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp.test_utils import AioHTTPTestCase

from launchpad.kafka import LaunchpadMessage
from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadConsumerService, LaunchpadWebService


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


class TestLaunchpadWebService:
    """Test cases for LaunchpadWebService."""

    @pytest.mark.asyncio
    async def test_setup(self):
        """Test that web service can be set up."""
        service = LaunchpadWebService()
        await service.setup()

        assert service.server is not None

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test the web service health check."""
        service = LaunchpadWebService()
        await service.setup()

        health = await service.health_check()

        assert health["service"] == "launchpad-web"
        assert health["status"] == "ok"
        assert "components" in health
        assert health["components"]["server"]["status"] == "ok"

    @pytest.mark.asyncio
    async def test_health_check_no_setup(self):
        """Test health check when service is not set up."""
        service = LaunchpadWebService()

        health = await service.health_check()

        assert health["service"] == "launchpad-web"
        assert health["status"] == "ok"
        assert health["components"]["server"]["status"] == "not_initialized"


class TestLaunchpadConsumerService:
    """Test cases for LaunchpadConsumerService."""

    @pytest.mark.asyncio
    async def test_setup(self):
        """Test that consumer service can be set up."""
        service = LaunchpadConsumerService()
        await service.setup()

        assert service.kafka_consumer is not None

    @pytest.mark.asyncio
    async def test_handle_kafka_message_ios(self):
        """Test handling iOS analysis messages."""
        service = LaunchpadConsumerService()

        # Mock the iOS analysis handler
        service._handle_ios_analysis_sync = Mock()

        # Create a mock message
        message = LaunchpadMessage(
            topic="test-topic",
            partition=0,
            offset=1,
            key=b"test-key",
            value=json.dumps({"type": "analyze_ios", "file_path": "/path/to/app.zip"}).encode(),
        )

        service.handle_kafka_message(message)

        # Verify the handler was called
        service._handle_ios_analysis_sync.assert_called_once_with(
            {"type": "analyze_ios", "file_path": "/path/to/app.zip"}
        )

    @pytest.mark.asyncio
    async def test_handle_kafka_message_android(self):
        """Test handling Android analysis messages."""
        service = LaunchpadConsumerService()

        # Mock the Android analysis handler
        service._handle_android_analysis_sync = Mock()

        # Create a mock message
        message = LaunchpadMessage(
            topic="test-topic",
            partition=0,
            offset=1,
            key=b"test-key",
            value=json.dumps({"type": "analyze_android", "file_path": "/path/to/app.apk"}).encode(),
        )

        service.handle_kafka_message(message)

        # Verify the handler was called
        service._handle_android_analysis_sync.assert_called_once_with(
            {"type": "analyze_android", "file_path": "/path/to/app.apk"}
        )

    @pytest.mark.asyncio
    async def test_handle_kafka_message_unknown_type(self):
        """Test handling messages with unknown type."""
        service = LaunchpadConsumerService()

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

    @pytest.mark.asyncio
    async def test_handle_kafka_message_invalid_json(self):
        """Test handling messages with invalid JSON."""
        service = LaunchpadConsumerService()

        # Create a mock message with invalid JSON
        message = LaunchpadMessage(topic="test-topic", partition=0, offset=1, key=b"test-key", value=b"invalid json")

        # This should not raise an exception
        service.handle_kafka_message(message)

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test the consumer service health check."""
        service = LaunchpadConsumerService()

        # Mock the Kafka consumer
        mock_kafka_consumer = Mock()
        mock_kafka_consumer.health_check = AsyncMock(
            return_value={
                "status": "ok",
                "topics": ["test-topic"],
            }
        )
        service.kafka_consumer = mock_kafka_consumer

        health = await service.health_check()

        assert health["service"] == "launchpad-consumer"
        assert health["status"] == "ok"
        assert "components" in health
        assert health["components"]["kafka"]["status"] == "ok"

    @pytest.mark.asyncio
    async def test_health_check_no_kafka(self):
        """Test health check when Kafka consumer is not set up."""
        service = LaunchpadConsumerService()

        health = await service.health_check()

        assert health["service"] == "launchpad-consumer"
        assert health["status"] == "ok"
        assert "components" in health
        # When kafka_consumer is None, no kafka component should be in health
        assert "kafka" not in health["components"]
