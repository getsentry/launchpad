"""Utility for extracting metadata from .sentry-cli-metadata.txt files in artifacts."""

import zipfile

from pathlib import Path
from typing import Dict, Optional

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

METADATA_FILENAME = ".sentry-cli-metadata.txt"


class ToolingMetadata:
    """Container for tooling version metadata extracted from artifacts."""

    def __init__(
        self,
        cli_version: Optional[str] = None,
        fastlane_plugin_version: Optional[str] = None,
        gradle_plugin_version: Optional[str] = None,
    ):
        self.cli_version = cli_version
        self.fastlane_plugin_version = fastlane_plugin_version
        self.gradle_plugin_version = gradle_plugin_version

    def __repr__(self) -> str:
        return f"ToolingMetadata(cli_version={self.cli_version}, fastlane_plugin_version={self.fastlane_plugin_version}, gradle_plugin_version={self.gradle_plugin_version})"


def extract_metadata_from_zip(zip_path: Path) -> ToolingMetadata:
    """Extract tooling metadata from a .sentry-cli-metadata.txt file inside a zip.

    Args:
        zip_path: Path to the zip file to search

    Returns:
        ToolingMetadata object with extracted version information
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Look for .sentry-cli-metadata.txt anywhere in the zip
            metadata_files = [name for name in zf.namelist() if name.endswith(METADATA_FILENAME)]

            if not metadata_files:
                logger.debug(f"No {METADATA_FILENAME} found in {zip_path}")
                return ToolingMetadata()

            # Use the first metadata file found
            metadata_file = metadata_files[0]
            logger.debug(f"Found metadata file: {metadata_file}")

            with zf.open(metadata_file) as f:
                content = f.read().decode("utf-8")
                return _parse_metadata_content(content)

    except Exception as e:
        logger.warning(f"Failed to extract metadata from {zip_path}: {e}")
        return ToolingMetadata()


def _parse_metadata_content(content: str) -> ToolingMetadata:
    """Parse the content of .sentry-cli-metadata.txt file.

    Expected format:
        sentry-cli-version: 2.58.2
        sentry-fastlane-plugin: 1.2.3
        sentry-gradle-plugin: 4.12.0

    Args:
        content: The text content of the metadata file

    Returns:
        ToolingMetadata object with parsed version information
    """
    metadata: Dict[str, str] = {}

    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        metadata[key] = value

    return ToolingMetadata(
        cli_version=metadata.get("sentry-cli-version"),
        fastlane_plugin_version=metadata.get("sentry-fastlane-plugin"),
        gradle_plugin_version=metadata.get("sentry-gradle-plugin"),
    )
