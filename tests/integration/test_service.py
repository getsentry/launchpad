"""Tests for the Launchpad service."""

from __future__ import annotations

from unittest.mock import Mock, patch

from aiohttp.test_utils import AioHTTPTestCase
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService


class TestHealthyLaunchpadServer(AioHTTPTestCase):
    """Test cases for LaunchpadServer."""

    async def get_application(self):
        """Create the application for testing."""

        def mock_health_check() -> bool:
            return True

        server = LaunchpadServer(health_check_callback=mock_health_check)
        return server.create_app()

    async def test_health_check(self):
        """Test the health check endpoint."""
        resp = await self.client.request("GET", "/health")
        assert resp.status == 200

        # The health check has to be *precisely* this to pass, you
        # can't add extra fields without changing the getsentry/ops
        # repo:
        assert await resp.text() == '{"status": "ok", "service": "launchpad"}'

    async def test_ready_check(self):
        """Test the readiness check endpoint."""
        resp = await self.client.request("GET", "/ready")
        assert resp.status == 200

        data = await resp.json()
        assert data == {
            "status": "ok",
            "service": "launchpad",
        }


class TestLaunchpadService:
    """Test cases for LaunchpadService."""

    @patch.object(LaunchpadService, "process_artifact")
    def test_handle_kafka_message_ios(self, mock_process):
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

        # Verify process_artifact was called with correct args
        mock_process.assert_called_once_with("ios-test-123", "test-project-ios", "test-org-123")

        # Verify metrics were recorded
        service._statsd.increment.assert_any_call("artifact.processing.started")
        service._statsd.increment.assert_any_call("artifact.processing.completed")

    @patch.object(LaunchpadService, "process_artifact")
    def test_handle_kafka_message_android(self, mock_process):
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

        # Verify process_artifact was called with correct args
        mock_process.assert_called_once_with("android-test-456", "test-project-android", "test-org-456")

        # Verify metrics were recorded
        service._statsd.increment.assert_any_call("artifact.processing.started")
        service._statsd.increment.assert_any_call("artifact.processing.completed")

    @patch.object(LaunchpadService, "process_artifact")
    def test_handle_kafka_message_error(self, mock_process):
        """Test error handling in message processing."""
        service = LaunchpadService()

        # Mock statsd
        service._statsd = Mock()

        # Make process_artifact raise an exception
        mock_process.side_effect = RuntimeError("Download failed: HTTP 404")

        # Create a valid payload
        payload: PreprodArtifactEvents = {
            "artifact_id": "test-123",
            "project_id": "test-project",
            "organization_id": "test-org",
        }

        # This should not raise (simplified error handling catches all exceptions)
        service.handle_kafka_message(payload)

        # Verify process_artifact was called
        mock_process.assert_called_once_with("test-123", "test-project", "test-org")

        # Verify the metrics were called correctly
        calls = service._statsd.increment.call_args_list
        assert len(calls) == 2
        assert calls[0][0][0] == "artifact.processing.started"
        assert calls[1][0][0] == "artifact.processing.failed"
