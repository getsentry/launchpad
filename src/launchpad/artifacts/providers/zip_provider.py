import zipfile

from pathlib import Path
from typing import List

from launchpad.utils.file_utils import cleanup_directory, create_temp_directory
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)

DEFAULT_MAX_FILE_COUNT = 100000
DEFAULT_MAX_UNCOMPRESSED_SIZE = 10 * 1024 * 1024 * 1024


class UnreasonableZipError(ValueError):
    """Raised when a zip file exceeds reasonable limits."""

    pass


class UnsafePathError(ValueError):
    """Raised when a zip file contains unsafe path entries that could lead to path traversal attacks."""

    pass


def check_reasonable_zip(
    zf: zipfile.ZipFile,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    max_uncompressed_size: int = DEFAULT_MAX_UNCOMPRESSED_SIZE,
) -> None:
    """Check if a zip file is reasonable based on file count and total uncompressed size.

    Args:
        zf: The ZipFile to check
        max_file_count: Maximum number of files allowed (default: 100,000)
        max_uncompressed_size: Maximum total uncompressed size in bytes (default: 10GB)

    Raises:
        UnreasonableZipError: If the zip exceeds the specified limits
    """
    info_list = zf.infolist()
    file_count = len(info_list)
    total_uncompressed_size = sum(info.file_size for info in info_list)

    if file_count > max_file_count:
        raise UnreasonableZipError(f"Zip file contains {file_count} files, exceeding the limit of {max_file_count}")

    if total_uncompressed_size > max_uncompressed_size:
        size_mb = total_uncompressed_size / (1024 * 1024)
        limit_mb = max_uncompressed_size / (1024 * 1024)
        raise UnreasonableZipError(
            f"Zip file uncompressed size is {size_mb:.1f}MB, exceeding the limit of {limit_mb:.1f}MB"
        )


def is_safe_path(base_dir: Path, requested_path: str) -> bool:
    """
    Ensure file operations occur within the intended directory
    Based on: https://medium.com/@contactomyna/securing-zip-file-operations-understanding-and-preventing-path-traversal-attacks-74d79f696c46
    """
    try:
        base_dir = base_dir.resolve()
        target_path = Path(base_dir, requested_path).resolve()
        return target_path.is_relative_to(base_dir)
    except RuntimeError:
        # Resolve raises RuntimeError prior to 3.13 for symlink loops.
        return False


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

        self._safe_extract(str(self.path), str(temp_dir))
        logger.debug(f"Extracted zip contents to {temp_dir}")

        return temp_dir

    def _safe_extract(self, zip_path: str, extract_path: str):
        """Extract the zip contents to a temporary directory, ensuring that the paths are safe from path traversal attacks.

        Supports both standard compression methods and Zstandard compression.
        """
        base_dir = Path(extract_path)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            check_reasonable_zip(zip_ref)
            for member in zip_ref.namelist():
                if is_safe_path(base_dir, member):
                    zip_ref.extract(member, extract_path)
                else:
                    raise UnsafePathError(f"Potential path traversal attack: {member}")

    def __del__(self) -> None:
        """Clean up resources when object is destroyed."""
        for temp_dir in self._temp_dirs:
            if temp_dir.exists():
                cleanup_directory(temp_dir)
