"""Tests for the Launchpad service."""

from __future__ import annotations

from unittest.mock import patch

from aiohttp.test_utils import AioHTTPTestCase
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService
from launchpad.utils.statsd import FakeStatsd


class TestHealthyLaunchpadServer(AioHTTPTestCase):
    """Test cases for LaunchpadServer."""

    async def get_application(self):
        """Create the application for testing."""

        def mock_health_check() -> bool:
            return True

        fake_statsd = FakeStatsd()
        server = LaunchpadServer(health_check_callback=mock_health_check, statsd=fake_statsd)
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
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

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
        calls = fake_statsd.calls
        assert ("increment", {"metric": "artifact.processing.started", "value": 1, "tags": None}) in calls
        assert ("increment", {"metric": "artifact.processing.completed", "value": 1, "tags": None}) in calls

    @patch.object(LaunchpadService, "process_artifact")
    def test_handle_kafka_message_android(self, mock_process):
        """Test handling Android artifact messages."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

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
        calls = fake_statsd.calls
        assert ("increment", {"metric": "artifact.processing.started", "value": 1, "tags": None}) in calls
        assert ("increment", {"metric": "artifact.processing.completed", "value": 1, "tags": None}) in calls

    @patch.object(LaunchpadService, "process_artifact")
    def test_handle_kafka_message_error(self, mock_process):
        """Test error handling in message processing."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

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
        calls = fake_statsd.calls
        increment_calls = [call for call in calls if call[0] == "increment"]
        assert len(increment_calls) == 2
        assert increment_calls[0][1]["metric"] == "artifact.processing.started"
        assert increment_calls[1][1]["metric"] == "artifact.processing.failed"
