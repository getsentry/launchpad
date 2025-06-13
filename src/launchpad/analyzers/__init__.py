"""Analyzers for different platforms."""

from .android import AndroidAnalyzer
from .ios import IOSAnalyzer

__all__ = ["AndroidAnalyzer", "IOSAnalyzer"]
