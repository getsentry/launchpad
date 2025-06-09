"""Platform-specific analyzers for app bundles."""

from .android import AndroidAnalyzer
from .ios import IOSAnalyzer

__all__ = [
    "IOSAnalyzer",
    "AndroidAnalyzer",
]
