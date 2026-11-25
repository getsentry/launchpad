"""Sentry SDK initialization for the Launchpad service."""

from __future__ import annotations

import logging
import os

from dataclasses import dataclass

import sentry_sdk

from sentry_sdk.integrations.aiohttp import AioHttpIntegration
from sentry_sdk.integrations.asyncio import AsyncioIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.integrations.stdlib import StdlibIntegration
from sentry_sdk.integrations.threading import ThreadingIntegration

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


def initialize_sentry_sdk(config: SentryConfig | None = None) -> None:
    """Initialize Sentry SDK with launchpad-specific configuration."""
    config = config or get_sentry_config()

    if config.environment.lower() in ("test", "development"):
        logger.debug(f"In {config.environment} environment, skipping Sentry SDK initialization")
        return

    if not config.dsn:
        logger.info("Sentry DSN not provided, skipping Sentry SDK initialization")
        return

    integrations = [
        AioHttpIntegration(),
        AsyncioIntegration(),
        LoggingIntegration(
            breadcrumb_level=logging.DEBUG,  # Capture debug and above as breadcrumbs
            event_level=logging.ERROR,  # SDK 3.x no longer creates events from logs by default
        ),
        StdlibIntegration(),
        ThreadingIntegration(propagate_scope=True),
    ]

    sentry_sdk.init(
        dsn=config.dsn,
        integrations=integrations,
        # SDK 3.x no longer scrubs sensitive local variables by default.
        data_collection={"stack_frame_variables": {"mode": "denylist"}},
        # SDK 3.x attaches stack traces to messages by default, which would regroup issues.
        attach_stacktrace=False,
        # Release is the git sha
        release=config.release,
        # Convention is to set the Sentry environment to the region (us, de, etc).
        environment=config.region,
        traces_sample_rate=1.0,  # Low volume service, capture all traces for now
    )

    logger.info(f"Sentry SDK initialized for environment: {config.region}")


@dataclass
class SentryConfig:
    """Sentry configuration data."""

    dsn: str | None
    environment: str
    release: str
    region: str | None


def get_sentry_config() -> SentryConfig:
    """Get Sentry configuration from environment variables."""
    environment = os.getenv("LAUNCHPAD_ENV")
    if not environment:
        raise ValueError("LAUNCHPAD_ENV environment variable is required")

    return SentryConfig(
        dsn=os.getenv("SENTRY_DSN"),
        environment=environment.lower(),
        release=os.getenv("LAUNCHPAD_VERSION_SHA", "unknown"),
        region=os.getenv("SENTRY_REGION", "unknown"),
    )
