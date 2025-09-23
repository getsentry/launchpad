"""Tests for the Launchpad service."""

from __future__ import annotations

from unittest.mock import patch

from aiohttp.test_utils import AioHTTPTestCase
from sentry_kafka_schemas.schema_types.preprod_artifact_events_v1 import (
    PreprodArtifactEvents,
)

from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService, PreprodFeature, ServiceConfig
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
            "requested_features": ["size_analysis"],
        }

        # handle_kafka_message is synchronous
        service.handle_kafka_message(payload)

        # Verify process_artifact was called with correct args
        mock_process.assert_called_once_with(
            "test-org-123", "test-project-ios", "ios-test-123", [PreprodFeature.SIZE_ANALYSIS]
        )

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
            "requested_features": ["size_analysis", "build_distribution"],
        }

        # handle_kafka_message is synchronous
        service.handle_kafka_message(payload)

        # Verify process_artifact was called with correct args
        mock_process.assert_called_once_with(
            "test-org-456",
            "test-project-android",
            "android-test-456",
            [PreprodFeature.SIZE_ANALYSIS, PreprodFeature.BUILD_DISTRIBUTION],
        )

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
            "requested_features": ["size_analysis", "build_distribution"],
        }

        # This should not raise (simplified error handling catches all exceptions)
        service.handle_kafka_message(payload)

        # Verify process_artifact was called
        mock_process.assert_called_once_with(
            "test-org", "test-project", "test-123", [PreprodFeature.SIZE_ANALYSIS, PreprodFeature.BUILD_DISTRIBUTION]
        )

        # Verify the metrics were called correctly
        calls = fake_statsd.calls
        increment_calls = [call for call in calls if call[0] == "increment"]
        assert len(increment_calls) == 2
        assert increment_calls[0][1]["metric"] == "artifact.processing.started"
        assert increment_calls[1][1]["metric"] == "artifact.processing.failed"

    @patch.object(LaunchpadService, "process_artifact")
    def test_handle_kafka_message_project_skipped(self, mock_process):
        """Test that projects in the skip list are not processed."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)
        service._service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io", projects_to_skip=["skip-project-1", "skip-project-2"]
        )

        # Create a payload for a project that should be skipped
        payload: PreprodArtifactEvents = {
            "artifact_id": "skip-test-123",
            "project_id": "skip-project-1",
            "organization_id": "test-org-123",
            "requested_features": ["size_analysis", "build_distribution"],
        }

        # handle_kafka_message should return early and not process
        service.handle_kafka_message(payload)

        # Verify process_artifact was NOT called
        mock_process.assert_not_called()

        # Verify no metrics were recorded (since processing was skipped entirely)
        calls = fake_statsd.calls
        assert len(calls) == 0

    @patch.object(LaunchpadService, "process_artifact")
    def test_handle_kafka_message_project_not_skipped(self, mock_process):
        """Test that projects not in the skip list are processed normally."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)
        service._service_config = ServiceConfig(
            sentry_base_url="http://test.sentry.io", projects_to_skip=["other-project"]
        )

        # Create a payload for a project that should NOT be skipped
        payload: PreprodArtifactEvents = {
            "artifact_id": "normal-test-123",
            "project_id": "normal-project",
            "organization_id": "test-org-123",
            "requested_features": ["size_analysis", "build_distribution"],
        }

        # handle_kafka_message should process normally
        service.handle_kafka_message(payload)

        # Verify process_artifact was called
        mock_process.assert_called_once_with(
            "test-org-123",
            "normal-project",
            "normal-test-123",
            [PreprodFeature.SIZE_ANALYSIS, PreprodFeature.BUILD_DISTRIBUTION],
        )

        # Verify normal metrics were recorded
        calls = fake_statsd.calls
        assert ("increment", {"metric": "artifact.processing.started", "value": 1, "tags": None}) in calls
        assert ("increment", {"metric": "artifact.processing.completed", "value": 1, "tags": None}) in calls
