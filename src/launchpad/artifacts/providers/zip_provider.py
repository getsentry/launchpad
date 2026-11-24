import zipfile

from collections.abc import Callable
from pathlib import Path
from typing import List

from launchpad.utils.file_utils import cleanup_directory, create_temp_directory
from launchpad.utils.logging import get_logger

from .exceptions import UnreasonableZipError
from .safe_directory import SafeDirectory

logger = get_logger(__name__)

DEFAULT_MAX_FILE_COUNT = 100000
DEFAULT_MAX_UNCOMPRESSED_SIZE = 10 * 1024 * 1024 * 1024


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


class ZipProvider:
    """Provider for handling zip file operations."""

    def __init__(self, path: Path) -> None:
        """Initialize the zip provider.

        Args:
            path: Path to the zip file
        """
        self.path = path
        self._temp_dirs: List[Path] = []

    def extract_to_temp_directory(
        self, *, on_extracted: Callable[[zipfile.ZipInfo, Path], None] | None = None
    ) -> SafeDirectory:
        """Extract the zip contents to a temporary directory.
        A new temporary directory is created for each call to this method.
        Each entry's path is checked for traversal before extraction.
        Supported ZIP compression methods include Zstandard.

        Args:
            on_extracted: Optional callback invoked after each entry is extracted.
                Receives the entry's ZipInfo and its extracted filesystem path.

        Returns:
            SafeDirectory wrapping the temporary directory containing extracted files
        """
        temp_dir = create_temp_directory("zip-extract-")
        self._temp_dirs.append(temp_dir)

        safe_dir = SafeDirectory(temp_dir)
        with zipfile.ZipFile(self.path, "r") as zip_ref:
            check_reasonable_zip(zip_ref)
            for member in zip_ref.infolist():
                safe_dir.resolve(member.filename)
                extracted = zip_ref.extract(member, safe_dir.path)
                if on_extracted is not None:
                    on_extracted(member, Path(extracted))
        logger.debug(f"Extracted zip contents to {temp_dir}")
        return safe_dir

    def __del__(self) -> None:
        """Clean up resources when object is destroyed."""
        for temp_dir in self._temp_dirs:
            if temp_dir.exists():
                cleanup_directory(temp_dir)
