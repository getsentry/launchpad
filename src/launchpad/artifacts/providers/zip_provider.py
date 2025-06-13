from io import BytesIO
from pathlib import Path
from typing import List
from zipfile import ZipFile

from launchpad.utils.file_utils import cleanup_directory, create_temp_directory
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class ZipProvider:
    """Provider for handling zip file operations."""

    def __init__(self, content: bytes) -> None:
        """Initialize the zip provider.

        Args:
            content: Raw bytes of the zip file
        """
        self.content = content
        self._zip: ZipFile | None = None
        self._temp_dirs: List[Path] = []

    def get_zip(self) -> ZipFile:
        """Get the ZipFile object, creating it if it doesn't exist.

        Returns:
            ZipFile object for accessing the archive contents
        """
        if self._zip is None:
            self._zip = ZipFile(BytesIO(self.content))
        return self._zip

    def extract_to_temp_directory(self) -> Path:
        """Extract the zip contents to a temporary directory.
        Creates a temporary directory and extracts the zip contents to it.
        A new temporary directory is created for each call to this method.

        Returns:
            Path to the temporary directory containing extracted files
        """
        temp_dir = create_temp_directory("zip-extract-")
        self._temp_dirs.append(temp_dir)

        zip = self.get_zip()
        with zip as zip_ref:
            zip_ref.extractall(temp_dir)
        logger.debug(f"Extracted zip contents to {temp_dir}")

        return temp_dir

    def __del__(self) -> None:
        """Clean up resources when object is destroyed."""
        if self._zip is not None:
            self._zip.close()

        # Clean up any temporary directories
        for temp_dir in self._temp_dirs:
            if temp_dir.exists():
                cleanup_directory(temp_dir)
