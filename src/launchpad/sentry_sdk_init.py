"""Sentry SDK initialization for the Launchpad service."""

from __future__ import annotations

import logging
import os

from typing import Any, Dict

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

    if config.get("environment") in ("TEST", "DEVELOPMENT"):
        logger.debug(f"In {config.get('environment')} environment, skipping Sentry SDK initialization")
        return

    if not config.get("dsn"):
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
        dsn=config["dsn"],
        integrations=integrations,
        send_default_pii=True,
        release=config.get("release"),
        environment=config.get("environment"),
    )

    if config.get("region"):
        sentry_sdk.set_tag("sentry_region", config["region"])

    logger.info(f"Sentry SDK initialized for environment: {config.get('environment')}")


def get_sentry_config() -> Dict[str, Any]:
    """Get Sentry configuration from environment variables."""
    environment = os.getenv("LAUNCHPAD_ENV")
    if not environment:
        raise ValueError("LAUNCHPAD_ENV environment variable is required")

    return {
        "dsn": os.getenv("SENTRY_DSN"),
        "environment": environment.lower(),
        "release": os.getenv("LAUNCHPAD_VERSION_SHA", "unknown"),  # TODO: auto fetch latest git commit hash
        "region": os.getenv("SENTRY_REGION"),
    }
