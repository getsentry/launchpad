from __future__ import annotations

from typing import TypeVar

import sentry_options

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

NAMESPACE = "launchpad"

T = TypeVar("T")

_init_ok: bool | None = None


def init_options() -> bool:
    global _init_ok
    if _init_ok is None:
        try:
            sentry_options.init()
            _init_ok = True
        except Exception:
            logger.exception("Failed to initialize sentry-options; option reads will use their fallbacks")
            _init_ok = False
    return _init_ok


def get_option(name: str, fallback: T) -> T:
    if not init_options():
        return fallback
    try:
        return sentry_options.options(NAMESPACE).get(name)
    except Exception:
        logger.warning("Failed to read sentry-option %r; using fallback", name, exc_info=True)
        return fallback
