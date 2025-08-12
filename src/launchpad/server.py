"""Launchpad HTTP server with health checks and async support."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from typing import Any, Callable, Dict

from aiohttp import web
from aiohttp.typedefs import Handler
from aiohttp.web import (
    AppKey,
    Application,
    Request,
    Response,
    StreamResponse,
    middleware,
)

from .utils.logging import get_logger
from .utils.statsd import get_statsd

logger = get_logger(__name__)

# Define app keys using AppKey
APP_KEY_DEBUG = AppKey("debug", bool)
APP_KEY_ENVIRONMENT = AppKey("environment", str)


@middleware
async def security_headers_middleware(request: Request, handler: Handler) -> StreamResponse:
    """Add security headers for production mode."""
    response = await handler(request)

    # Only add security headers in production
    if not request.app.get(APP_KEY_DEBUG, False):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


class LaunchpadServer:
    """Main server class for Launchpad."""

    _running: bool
    health_check_callback: Callable[[], bool]

    def __init__(
        self,
        health_check_callback: Callable[[], bool],
        host: str | None = None,
        port: int | None = None,
        config: Dict[str, Any] | None = None,
        setup_logging: bool = True,
    ) -> None:
        self.app: Application | None = None
        self._running = False
        self._shutdown_event = asyncio.Event()
        self.config = config or get_server_config()
        self.health_check_callback = health_check_callback
        self._statsd = get_statsd()

        # Override config with explicit parameters if provided
        if host is not None:
            self.config["host"] = host
        if port is not None:
            self.config["port"] = port

        self.host = self.config["host"]
        self.port = self.config["port"]

        # Only setup logging if requested (CLI handles its own logging)
        if setup_logging:
            self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging based on environment."""
        log_level = getattr(logging, self.config["log_level"])

        # Only configure if logging hasn't been configured yet
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=log_level,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                stream=sys.stdout,
            )

        # Adjust aiohttp access log level
        if not self.config["access_log"]:
            logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

    def create_app(self) -> Application:
        """Create the aiohttp application with routes."""
        middlewares = [security_headers_middleware] if not self.config["debug"] else []

        app = web.Application(
            middlewares=middlewares,
        )

        # Store config in app using AppKey
        app[APP_KEY_DEBUG] = self.config["debug"]
        app[APP_KEY_ENVIRONMENT] = self.config["environment"]

        app.router.add_get("/health", self.health_check)
        app.router.add_get("/ready", self.health_check)
        return app

    def health_check(self, request: Request) -> Response:
        is_healthy = self.health_check_callback()
        environment = self.config["environment"]
        self._statsd.service_check(
            "launchpad.health_check",
            self._statsd.OK if is_healthy else self._statsd.CRITICAL,
            tags=[f"environment:{environment}"],
        )
        if is_healthy:
            logger.debug("launchpad healthy")
        else:
            logger.warning("launchpad unhealthy - but reporting healthy")
        return web.json_response(
            {
                "status": "ok",
                "service": "launchpad",
            }
        )

    async def start(self):
        """Start the HTTP server."""
        logger.info(f"{self} start commanded")
        self._task = asyncio.create_task(self.run())

    async def run(self):
        assert not self._running, "Already running"
        logger.info(f"{self} running")
        self._running = True
        self.app = self.create_app()

        runner = web.AppRunner(
            self.app,
            access_log=logger if self.config["access_log"] else None,
        )
        await runner.setup()

        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        logger.info(
            f"Launchpad server started on {self.host}:{self.port} "
            f"(environment: {self.config['environment']}, debug: {self.config['debug']})"
        )

        await self._shutdown_event.wait()

        logger.info("Shutting down server...")
        await runner.cleanup()
        self._running = False

    async def stop(self, timeout_s=10):
        logger.info(f"{self} stop commanded")
        self._shutdown_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=timeout_s)
        except asyncio.TimeoutError:
            logger.warning(f"{self} did not stop within timeout {timeout_s}s")
            self._task.cancel()


def get_server_config() -> Dict[str, Any]:
    """Get server configuration from environment."""
    environment = os.getenv("LAUNCHPAD_ENV")
    if not environment:
        raise ValueError("LAUNCHPAD_ENV environment variable is required")
    environment = environment.lower()

    is_production = environment == "production"

    host = os.getenv("LAUNCHPAD_HOST")
    if not host:
        raise ValueError("LAUNCHPAD_HOST environment variable is required")

    port_str = os.getenv("LAUNCHPAD_PORT")
    if not port_str:
        raise ValueError("LAUNCHPAD_PORT environment variable is required")

    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(  # noqa: E501
            f"LAUNCHPAD_PORT must be a valid integer, got: {port_str}"
        )

    return {
        "environment": environment,
        "host": host,
        "port": port,
        "debug": not is_production,
        "log_level": "WARNING" if is_production else "DEBUG",
        "access_log": not is_production,  # Disable access logs in prod
    }
