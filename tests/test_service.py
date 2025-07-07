"""Tests for the Launchpad service."""

from __future__ import annotations

import os
import time

from unittest.mock import Mock

import pytest

from aiohttp.test_utils import AioHTTPTestCase
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.server import HealthCheckResponse, LaunchpadServer
from launchpad.service import LaunchpadService


class TestLaunchpadServer(AioHTTPTestCase):
    """Test cases for LaunchpadServer."""

    async def get_application(self):
        """Create the application for testing."""

        # Create a mock health check callback
        async def mock_health_check() -> HealthCheckResponse:
            return {
                "service": "launchpad",
                "status": "ok",
                "components": {
                    "kafka": {"status": "healthy"},
                    "server": {"status": "ok"},
                },
            }

        server = LaunchpadServer(health_check_callback=mock_health_check)
        return await server.create_app()

    async def test_health_check(self):
        """Test the health check endpoint."""
        resp = await self.client.request("GET", "/health")
        assert resp.status == 200

        data = await resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "launchpad"
        assert "components" in data

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
        """Test handling iOS artifact messages."""
        service = LaunchpadService()

        # Mock statsd
        service._statsd = Mock()

        # Create a payload for iOS artifact
        payload: PreprodArtifactEvents = {
            "artifact_id": "ios-test-123",
            "project_id": "test-project-ios",
            "organization_id": "test-org-123",
        }

        # handle_kafka_message is synchronous
        service.handle_kafka_message(payload)

        # Verify metrics were recorded
        service._statsd.increment.assert_any_call("launchpad.artifact.processing.started")
        service._statsd.increment.assert_any_call("launchpad.artifact.processing.completed")

    def test_handle_kafka_message_android(self):
        """Test handling Android artifact messages."""
        service = LaunchpadService()

        # Mock statsd
        service._statsd = Mock()

        # Create a payload for Android artifact
        payload: PreprodArtifactEvents = {
            "artifact_id": "android-test-456",
            "project_id": "test-project-android",
            "organization_id": "test-org-456",
        }

        # handle_kafka_message is synchronous
        service.handle_kafka_message(payload)

        # Verify metrics were recorded
        service._statsd.increment.assert_any_call("launchpad.artifact.processing.started")
        service._statsd.increment.assert_any_call("launchpad.artifact.processing.completed")

    def test_handle_kafka_message_error(self):
        """Test error handling in message processing."""
        service = LaunchpadService()

        # Mock statsd to raise an exception on the second call
        service._statsd = Mock()
        service._statsd.increment.side_effect = [
            None,  # First call: processing.started
            Exception("Simulated error"),  # Second call: processing.completed (raises)
            None,  # Third call: processing.failed
        ]

        # Create a valid payload
        payload: PreprodArtifactEvents = {
            "artifact_id": "test-123",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        # This should raise the exception (to be handled by Arroyo)
        with pytest.raises(Exception, match="Simulated error"):
            service.handle_kafka_message(payload)

        # Verify the metrics were called in the expected order
        calls = service._statsd.increment.call_args_list
        assert len(calls) == 3
        assert calls[0][0][0] == "launchpad.artifact.processing.started"
        assert calls[1][0][0] == "launchpad.artifact.processing.completed"
        assert calls[2][0][0] == "launchpad.artifact.processing.failed"

    @pytest.mark.asyncio
    async def test_health_check_with_healthcheck_file(self, tmp_path):
        """Test the service health check with healthcheck file."""
        service = LaunchpadService()

        # Create a temporary healthcheck file
        healthcheck_file = tmp_path / "healthcheck"
        healthcheck_file.touch()

        service._healthcheck_file = str(healthcheck_file)
        service.server = Mock()

        # Test healthy state (recently touched file)
        health = await service.health_check()
        assert health["service"] == "launchpad"
        assert health["status"] == "ok"
        assert health["components"]["kafka"]["status"] == "healthy"

        # Test unhealthy state (old file)
        # Set file modification time to 2 minutes ago
        old_time = time.time() - 120
        os.utime(healthcheck_file, (old_time, old_time))

        health = await service.health_check()
        assert health["status"] == "degraded"
        assert health["components"]["kafka"]["status"] == "unhealthy"
        assert "No heartbeat" in health["components"]["kafka"]["reason"]
