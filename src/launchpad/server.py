"""Launchpad HTTP server with health checks and async support."""

from __future__ import annotations

import asyncio
import logging
import os

from typing import Any, Awaitable, Callable, Dict, TypedDict

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

logger = get_logger(__name__)

# Define app keys using AppKey
APP_KEY_DEBUG = AppKey("debug", bool)
APP_KEY_ENVIRONMENT = AppKey("environment", str)


class HealthCheckResponse(TypedDict, total=False):
    """Health check response with minimal required fields."""

    status: str  # Required: "ok", "degraded", "error"
    service: str
    components: Dict[str, Dict[str, Any]]
    environment: str
    version: str
    error: str
    warning: str


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

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        config: Dict[str, Any] | None = None,
        setup_logging: bool = True,
        health_check_callback: (Callable[[], Awaitable[HealthCheckResponse]] | None) = None,
    ) -> None:
        self.app: Application | None = None
        self._shutdown_event = asyncio.Event()
        self.config = config or get_server_config()
        self.health_check_callback = health_check_callback

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
            )

        # Adjust aiohttp access log level
        if not self.config["access_log"]:
            logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

    async def create_app(self) -> Application:
        """Create the aiohttp application with routes."""
        middlewares = [security_headers_middleware] if not self.config["debug"] else []

        app = web.Application(
            middlewares=middlewares,
        )

        # Store config in app using AppKey
        app[APP_KEY_DEBUG] = self.config["debug"]
        app[APP_KEY_ENVIRONMENT] = self.config["environment"]

        # Health check routes
        app.router.add_get("/health", self.health_check)

        # Ready check route
        app.router.add_get("/ready", self.ready_check)

        return app

    async def health_check(self, request: Request) -> Response:
        """Health check endpoint that checks all service components."""
        try:
            # Get health status from the service if callback is provided
            if self.health_check_callback:
                try:
                    health_data = await self.health_check_callback()

                    # Basic validation - just ensure we have a status
                    if not isinstance(health_data, dict) or "status" not in health_data:
                        raise ValueError("Invalid health check response")

                    # Map status to HTTP code
                    status_code = {"ok": 200, "degraded": 503}.get(health_data["status"], 500)
                    return web.json_response(health_data, status=status_code)

                except Exception as e:
                    logger.error(f"Health check callback failed: {e}", exc_info=True)
                    return web.json_response(
                        {
                            "status": "error",
                            "service": "launchpad",
                            "error": str(e),
                        },
                        status=500,
                    )
            else:
                # Fallback to basic health check if no callback
                return web.json_response(
                    {
                        "status": "ok",
                        "service": "launchpad",
                        "version": "0.0.1",
                        "environment": self.config["environment"],
                        "warning": "No service health check callback configured",
                    }
                )
        except Exception as e:
            logger.error(f"Health check failed: {e}", exc_info=True)
            return web.json_response({"status": "error", "service": "launchpad", "error": str(e)}, status=500)

    async def ready_check(self, request: Request) -> Response:
        """Readiness check endpoint."""
        # TODO: Add actual readiness checks (database connectivity, etc.)
        return web.json_response(
            {
                "status": "ready",
                "service": "launchpad",
                "environment": self.config["environment"],
            }
        )

    async def start(self) -> None:
        """Start the HTTP server."""
        self.app = await self.create_app()

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

        # Wait for shutdown signal
        await self._shutdown_event.wait()

        logger.info("Shutting down server...")
        await runner.cleanup()

    def shutdown(self) -> None:
        """Signal the server to shutdown."""
        self._shutdown_event.set()


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
