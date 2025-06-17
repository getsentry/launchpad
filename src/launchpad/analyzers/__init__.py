"""Analyzers for different platforms."""

from .android import AndroidAnalyzer
from .apple import AppleAppAnalyzer

__all__ = ["AndroidAnalyzer", "AppleAppAnalyzer"]
