import hashlib
import shutil
import tempfile

from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import IO

from .logging import get_logger

logger = get_logger(__name__)

_HASH_CHUNK_SIZE = 8192


class IdPrefix(Enum):
    ICON = "icn"
    SNAPSHOT = "snap"


def _calculate_hash(data: IO[bytes], algorithm: str) -> str:
    hasher = None
    if algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "sha256":
        hasher = hashlib.sha256()

    if hasher is None:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    for chunk in iter(lambda: data.read(_HASH_CHUNK_SIZE), b""):
        hasher.update(chunk)

    return hasher.hexdigest()


def id_from_bytes(data: bytes, prefix: IdPrefix) -> str:
    return f"{prefix.value}_{_calculate_hash(BytesIO(data), 'sha256')[:12]}"


def calculate_file_hash(file_path: Path, algorithm: str = "md5") -> str:
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with open(file_path, "rb") as f:
            return _calculate_hash(f, algorithm)
    except Exception as e:
        raise RuntimeError(f"Failed to calculate hash for {file_path}: {e}")


def get_file_size(file_path: Path) -> int:
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    return file_path.stat().st_size


def to_nearest_block_size(file_size: int, block_size: int) -> int:
    if file_size == 0:
        return 0

    return ((file_size - 1) // block_size + 1) * block_size


def create_temp_directory(prefix: str = "app-analyzer-") -> Path:
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
    logger.debug(f"Created temporary directory: {temp_dir}")
    return temp_dir


def cleanup_directory(directory: Path) -> None:
    if directory.exists() and directory.is_dir():
        shutil.rmtree(directory)
        logger.debug(f"Cleaned up directory: {directory}")
