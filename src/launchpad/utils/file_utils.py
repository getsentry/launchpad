"""File utilities for app size analyzer."""

import hashlib
import shutil
import tempfile
from pathlib import Path

from ..models.common import FileInfo
from .logging import get_logger

logger = get_logger(__name__)


def calculate_file_hash(file_path: Path, algorithm: str = "md5") -> str:
    """Calculate hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use ("md5", "sha1", "sha256")

    Returns:
        Hexadecimal hash string

    Raises:
        ValueError: If algorithm is not supported
        FileNotFoundError: If file doesn't exist
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "sha256":
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)

        return hasher.hexdigest()
    except Exception as e:
        raise RuntimeError(f"Failed to calculate hash for {file_path}: {e}")


def get_file_size(file_path: Path) -> int:
    """Get file size in bytes.

    Args:
        file_path: Path to the file

    Returns:
        File size in bytes

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    return file_path.stat().st_size


def create_temp_directory(prefix: str = "app-analyzer-") -> Path:
    """Create a temporary directory.

    Args:
        prefix: Prefix for the temporary directory name

    Returns:
        Path to the created temporary directory
    """
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
    logger.debug(f"Created temporary directory: {temp_dir}")
    return temp_dir


def cleanup_directory(directory: Path) -> None:
    """Remove a directory and all its contents.

    Args:
        directory: Directory to remove
    """
    if directory.exists() and directory.is_dir():
        shutil.rmtree(directory)
        logger.debug(f"Cleaned up directory: {directory}")


def calculate_aligned_install_size(file_info: FileInfo, filesystem_block_size: int) -> int:
    """Calculate the aligned install size of a file.

    Args:
        file_info: File information
        filesystem_block_size: Filesystem block size
    """
    file_size = file_info.size
    if file_size == 0:
        return 0

    # Round up to nearest filesystem block boundary
    return ((file_size - 1) // filesystem_block_size + 1) * filesystem_block_size
