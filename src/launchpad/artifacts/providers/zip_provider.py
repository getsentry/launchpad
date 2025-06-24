import subprocess

from pathlib import Path
from typing import List

from launchpad.utils.file_utils import cleanup_directory, create_temp_directory
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class ZipProvider:
    """Provider for handling zip file operations."""

    def __init__(self, path: Path) -> None:
        """Initialize the zip provider.

        Args:
            path: Path to the zip file
        """
        self.path = path
        self._temp_dirs: List[Path] = []

    def extract_to_temp_directory(self) -> Path:
        """Extract the zip contents to a temporary directory.
        Creates a temporary directory and extracts the zip contents to it.
        A new temporary directory is created for each call to this method.

        Returns:
            Path to the temporary directory containing extracted files
        """
        temp_dir = create_temp_directory("zip-extract-")
        self._temp_dirs.append(temp_dir)

        try:
            # Use system unzip command to preserve symlinks and metadata
            subprocess.run(["unzip", "-q", str(self.path), "-d", str(temp_dir)], check=True, capture_output=True)

            logger.debug(f"Extracted zip contents to {temp_dir} using system unzip")
        except Exception as e:
            logger.error(f"Failed to extract zip contents to {temp_dir}: {e}")
            raise e

        return temp_dir

    def __del__(self) -> None:
        """Clean up resources when object is destroyed."""
        # Clean up any temporary directories
        for temp_dir in self._temp_dirs:
            if temp_dir.exists():
                cleanup_directory(temp_dir)
