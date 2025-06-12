"""Launchpad - CLI tool for analyzing iOS and Android app bundle sizes."""

__version__ = "0.0.1"

from .models import FileAnalysis

__all__ = [
    "FileAnalysis",
]
