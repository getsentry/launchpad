"""File utilities for app size analyzer."""

import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path

from .logging import get_logger

logger = get_logger(__name__)


def extract_archive(archive_path: Path, destination: Path) -> None:
    """Extract an archive to the destination directory.

    Args:
        archive_path: Path to the archive file
        destination: Destination directory for extraction

    Raises:
        ValueError: If archive format is not supported
        RuntimeError: If extraction fails
    """
    destination.mkdir(parents=True, exist_ok=True)

    suffix = archive_path.suffix.lower()

    if suffix == ".zip" or suffix == ".ipa":
        _extract_zip(archive_path, destination)
    else:
        raise ValueError(f"Unsupported archive format: {suffix}")


def _extract_zip(archive_path: Path, destination: Path) -> None:
    """Extract a ZIP archive using Python's zipfile module."""
    try:
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            zip_ref.extractall(destination)
        logger.debug(f"Extracted {archive_path} to {destination}")
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"Invalid ZIP archive: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to extract archive: {e}")


def find_app_bundle(directory: Path, platform: str = "ios") -> Path:
    """Find an app bundle in the given directory.

    Args:
        directory: Directory to search in
        platform: Target platform ("ios" or "android")

    Returns:
        Path to the found app bundle

    Raises:
        FileNotFoundError: If no app bundle is found
    """
    if platform == "ios":
        return _find_ios_app_bundle(directory)
    elif platform == "android":
        return _find_android_app_bundle(directory)
    else:
        raise ValueError(f"Unsupported platform: {platform}")


def _find_ios_app_bundle(directory: Path) -> Path:
    """Find an iOS .app bundle in the directory tree."""
    # Look for .app directories
    for item in directory.rglob("*.app"):
        if item.is_dir():
            logger.debug(f"Found iOS app bundle: {item}")
            return item

    raise FileNotFoundError(f"No .app bundle found in {directory}")


def _find_android_app_bundle(directory: Path) -> Path:
    """Find an Android .apk file in the directory tree."""
    # Look for .apk files
    for item in directory.rglob("*.apk"):
        if item.is_file():
            logger.debug(f"Found Android app bundle: {item}")
            return item

    raise FileNotFoundError(f"No .apk file found in {directory}")


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
