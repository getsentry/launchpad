import zipfile

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
            self._safe_extract(str(self.path), str(temp_dir))
            logger.debug(f"Extracted zip contents to {temp_dir} using system unzip")
        except Exception as e:
            logger.error(f"Failed to extract zip contents to {temp_dir}: {e}")
            raise e

        return temp_dir

    def _safe_extract(self, zip_path: str, extract_path: str):
        """Extract the zip contents to a temporary directory, ensuring that the paths are safe from path traversal attacks."""
        base_dir = Path(extract_path)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            for member in zip_ref.namelist():
                if self._is_safe_path(base_dir, member):
                    zip_ref.extract(member, extract_path)
                else:
                    raise ValueError(f"Potential path traversal attack: {member}")

    def _is_safe_path(self, base_dir: Path, requested_path: str) -> bool:
        """
        Ensure file operations occur within the intended directory
        Based on: https://medium.com/@contactomyna/securing-zip-file-operations-understanding-and-preventing-path-traversal-attacks-74d79f696c46
        """
        try:
            base_dir = base_dir.resolve()
            target_path = Path(base_dir, requested_path).resolve()
            return target_path.is_relative_to(base_dir)
        except (RuntimeError, ValueError):
            return False

    def __del__(self) -> None:
        """Clean up resources when object is destroyed."""
        # Clean up any temporary directories
        for temp_dir in self._temp_dirs:
            if temp_dir.exists():
                cleanup_directory(temp_dir)
