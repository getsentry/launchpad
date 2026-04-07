"""Tests for the Launchpad HTTP server."""

from __future__ import annotations

from aiohttp.test_utils import AioHTTPTestCase

from launchpad.server import LaunchpadServer
from launchpad.utils.statsd import FakeStatsd


class TestHealthyLaunchpadServer(AioHTTPTestCase):
    async def get_application(self):
        def mock_health_check() -> bool:
            return True

        fake_statsd = FakeStatsd()
        server = LaunchpadServer(health_check_callback=mock_health_check, statsd=fake_statsd)
        return server.create_app()

    async def test_health_check(self):
        resp = await self.client.request("GET", "/health")
        assert resp.status == 200

        # The health check has to be *precisely* this to pass, you
        # can't add extra fields without changing the getsentry/ops
        # repo:
        assert await resp.text() == '{"status": "ok", "service": "launchpad"}'

    async def test_ready_check(self):
        resp = await self.client.request("GET", "/ready")
        assert resp.status == 200

        data = await resp.json()
        assert data == {
            "status": "ok",
            "service": "launchpad",
        }
