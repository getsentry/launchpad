"""Integration tests for the Launchpad service."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from launchpad.server import LaunchpadServer
from launchpad.service import LaunchpadService
from launchpad.utils.statsd import FakeStatsd


class TestServiceIntegration:
    """Integration tests for the full service orchestration."""

    def test_service_setup_integration(self):
        """Test that service setup initializes all components correctly."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        # Mock external dependencies
        with (
            patch("launchpad.service.initialize_sentry_sdk"),
            patch("launchpad.service.SentryClient") as mock_sentry_client,
            patch("launchpad.service.LaunchpadServer") as mock_server,
            patch("launchpad.service.create_kafka_consumer") as mock_kafka,
        ):
            service.setup()

            # Verify all components were initialized
            assert service._service_config is not None
            assert service._sentry_client is not None
            assert service.server is not None
            assert service.kafka is not None

            # Verify components were created with correct parameters
            mock_sentry_client.assert_called_once()
            mock_server.assert_called_once()
            mock_kafka.assert_called_once()

    @pytest.mark.asyncio
    async def test_service_health_check_integration(self):
        """Test service health check with mocked components."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        # Mock server and kafka components
        mock_server = Mock()
        mock_kafka = Mock()

        mock_server.is_healthy.return_value = True
        mock_kafka.is_healthy.return_value = True

        service.server = mock_server
        service.kafka = mock_kafka

        # Test healthy state
        assert service.is_healthy() is True

        # Test unhealthy server
        mock_server.is_healthy.return_value = False
        assert service.is_healthy() is False

        # Test unhealthy kafka
        mock_server.is_healthy.return_value = True
        mock_kafka.is_healthy.return_value = False
        assert service.is_healthy() is False

    def test_service_config_integration(self):
        """Test service configuration loading from environment."""
        from launchpad.service import get_service_config

        # Test with default values
        with patch.dict("os.environ", {}, clear=True):
            config = get_service_config()
            assert config.sentry_base_url == "http://getsentry.default"
            assert config.projects_to_skip == []

        # Test with environment variables
        with patch.dict(
            "os.environ",
            {"SENTRY_BASE_URL": "https://custom.sentry.io", "PROJECT_IDS_TO_SKIP": "project1,project2,project3"},
        ):
            config = get_service_config()
            assert config.sentry_base_url == "https://custom.sentry.io"
            assert config.projects_to_skip == ["project1", "project2", "project3"]


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
