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


def initialize_sentry_sdk() -> None:
    """Initialize Sentry SDK with launchpad-specific configuration."""
    config = get_sentry_config()

    if config.environment.lower() in ("test", "development"):
        logger.debug(f"In {config.environment} environment, skipping Sentry SDK initialization")
        return

    if not config.dsn:
        logger.info("Sentry DSN not provided, skipping Sentry SDK initialization")
        return

    integrations = [
        AioHttpIntegration(transaction_style="method_and_path_pattern"),
        AsyncioIntegration(),
        LoggingIntegration(
            level=logging.DEBUG,  # Capture debug and above as breadcrumbs
        ),
        StdlibIntegration(),
        ThreadingIntegration(propagate_hub=True),
    ]

    sentry_sdk.init(
        dsn=config.dsn,
        integrations=integrations,
        send_default_pii=True,
        # Release is the git sha
        release=config.release,
        # Convention is to set the Sentry environment to the region (us, de, etc).
        enable_logs=True,
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
