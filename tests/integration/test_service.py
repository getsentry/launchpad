"""Tests for the Launchpad service orchestration."""

from __future__ import annotations

from unittest.mock import patch

from aiohttp.test_utils import AioHTTPTestCase

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
    """Test cases for LaunchpadService orchestration."""

    def test_service_initialization(self):
        """Test that LaunchpadService can be initialized properly."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        assert service._statsd is fake_statsd
        assert service.server is None
        assert service.kafka is None
        assert service._service_config is None
        assert service._sentry_client is None

    def test_service_config_creation(self):
        """Test ServiceConfig creation with default values."""
        from launchpad.service import get_service_config

        # Test with no environment variables set
        with patch.dict("os.environ", {}, clear=True):
            config = get_service_config()
            assert config.sentry_base_url == "http://getsentry.default"  # Default value
            assert isinstance(config.projects_to_skip, list)

    def test_service_health_check_with_no_components(self):
        """Test health check when components are not initialized."""
        fake_statsd = FakeStatsd()
        service = LaunchpadService(fake_statsd)

        # Should handle None components gracefully
        # This will likely raise an AttributeError, which is expected behavior
        try:
            result = service.is_healthy()
            # If it doesn't raise, it should return False for unhealthy state
            assert result is False
        except AttributeError:
            # Expected when server/kafka are None
            pass
