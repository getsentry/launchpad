"""App Size Analyzer - CLI tool for analyzing iOS and Android app bundle sizes."""

__version__ = "0.0.1"

from .models.results import AnalysisResults, AppInfo, FileAnalysis, BinaryAnalysis

__all__ = [
    "AnalysisResults",
    "AppInfo",
    "FileAnalysis",
    "BinaryAnalysis",
]
