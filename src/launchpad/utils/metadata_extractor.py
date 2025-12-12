import zipfile

from pathlib import Path
from typing import Dict, Optional

from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

METADATA_FILENAME = ".sentry-cli-metadata.txt"


class ToolingMetadata:
    def __init__(
        self,
        cli_version: Optional[str] = None,
        fastlane_plugin_version: Optional[str] = None,
        gradle_plugin_version: Optional[str] = None,
    ):
        self.cli_version = cli_version
        self.fastlane_plugin_version = fastlane_plugin_version
        self.gradle_plugin_version = gradle_plugin_version


def extract_metadata_from_zip(zip_path: Path) -> ToolingMetadata:
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Only look for .sentry-cli-metadata.txt in the root of the zip
            if METADATA_FILENAME not in zf.namelist():
                logger.debug(f"No {METADATA_FILENAME} found in root of {zip_path}")
                return ToolingMetadata()

            logger.debug(f"Found metadata file: {METADATA_FILENAME}")

            with zf.open(METADATA_FILENAME) as f:
                content = f.read().decode("utf-8")
                return _parse_metadata_content(content)

    except Exception as e:
        logger.warning(f"Failed to extract metadata from {zip_path}: {e}")
        return ToolingMetadata()


def _parse_metadata_content(content: str) -> ToolingMetadata:
    """Expected format:
    sentry-cli-version: 2.58.2
    sentry-fastlane-plugin: 1.2.3
    sentry-gradle-plugin: 4.12.0
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
