"""App Size Analyzer - CLI tool for analyzing iOS and Android app bundle sizes."""

__version__ = "1.0.0"
__author__ = "Sentry Team"
__email__ = "engineering@sentry.io"

from .models.results import AnalysisResults, AppInfo, BinaryAnalysis, FileAnalysis

__all__ = [
    "AnalysisResults",
    "AppInfo",
    "FileAnalysis",
    "BinaryAnalysis",
]
