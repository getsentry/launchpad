import os
import subprocess
import tempfile
import uuid

from pathlib import Path
from typing import Tuple

import liblzfse

from launchpad.parsers.apple.macho_parser import MachOParser
from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.utils.file_utils import get_file_size, to_nearest_block_size
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


def calculate_bundle_sizes(bundle_url: Path) -> Tuple[int, int]:
    """Calculate the download and install sizes for an Apple app bundle."""

    if not bundle_url.exists():
        raise ValueError(f"Bundle not found: {bundle_url}")

    if bundle_url.suffix != ".app":
        raise ValueError(f"Only .app bundles are supported, got: {bundle_url}")

    install_size = _calculate_app_store_size(bundle_url)
    metadata_size = _zip_metadata_size_for_bundle(bundle_url)
    lzfse_size = _lzfse_content_size_for_bundle(bundle_url)
    signature_size = _get_extra_code_signature_size(bundle_url)
    download_size = metadata_size + lzfse_size + signature_size

    logger.debug(
        f"Bundle size breakdown - "
        f"ZIP metadata: {metadata_size} bytes, "
        f"LZFSE content: {lzfse_size} bytes, "
        f"Code signature: {signature_size} bytes, "
        f"Total download: {download_size} bytes, "
        f"Total install: {install_size} bytes"
    )

    return download_size, install_size


def _calculate_app_store_size(bundle_url: Path) -> int:
    total_size = 0
    file_count = 0

    # Walk through all files in the bundle
    for file_path in bundle_url.rglob("*"):
        if file_path.is_symlink():
            # Symlinks have 0 disk space
            file_count += 1
            continue

        if not file_path.is_file():
            continue

        file_count += 1

        # Add file size (rounded to 4KB blocks)
        total_size += to_nearest_block_size(get_file_size(file_path), APPLE_FILESYSTEM_BLOCK_SIZE)

        # Add extra code signature size for binaries without extensions
        if not file_path.suffix and MachOParser.is_macho_binary(file_path):
            total_size += _get_extra_code_signature_size(file_path)

    # Add directory size itself
    total_size += to_nearest_block_size(get_file_size(bundle_url), APPLE_FILESYSTEM_BLOCK_SIZE)
    file_count += 1

    logger.info(f"App Store size calculation: {file_count} files, {total_size} bytes")

    return total_size


def _lzfse_compressed_size(file_path: Path) -> int:
    try:
        with open(file_path, "rb") as f:
            source_data = f.read()

        source_size = len(source_data)

        compressed_data = liblzfse.compress(source_data)  # type: ignore
        compressed_size = len(compressed_data)  # type: ignore

        return compressed_size if compressed_size < source_size else source_size

    except Exception as e:
        logger.error(f"Error compressing {file_path}: {e}")
        return os.path.getsize(file_path)


def _zip_metadata_size_for_bundle(bundle_url: Path) -> int:
    temp_dir = Path(tempfile.gettempdir())
    zip_file_path = temp_dir / f"{uuid.uuid4()}.zip"
    zip_info_file_path = temp_dir / f"{uuid.uuid4()}.txt"
    bundle_dir = bundle_url.parent
    bundle_name = bundle_url.name

    try:
        logger.info(f"Creating ZIP file: zip -r {zip_file_path} {bundle_name}")
        result = subprocess.run(
            f'zip -r "{zip_file_path}" "{bundle_name}"', shell=True, capture_output=True, text=True, cwd=str(bundle_dir)
        )
        if result.returncode != 0:
            logger.error(f"ZIP command failed: {result.stderr}")
            return 0

        logger.info(f"Getting ZIP info: unzip -v {zip_file_path}")
        result = subprocess.run(
            f'unzip -v "{zip_file_path}"',
            shell=True,
            capture_output=True,
            text=True,
            stdout=open(zip_info_file_path, "w"),
        )
        if result.returncode != 0:
            logger.error(f"Unzip command failed: {result.stderr}")
            return 0

        with open(zip_info_file_path, "r", encoding="utf-8", errors="replace") as f:
            zip_info = f.read()

        # Parse the last line which contains total sizes
        lines = zip_info.strip().split("\n")
        last_line = lines[-1]
        # Format is typically: "--------          -------  ---                     -------"
        # followed by: "12345678         12345678  0%                 123 files"
        # The columns are: uncompressed_size compressed_size ratio file_count
        parts = last_line.split()
        if len(parts) >= 2:
            # total_uncompressed = int(parts[0])
            total_compressed = int(parts[1])
        else:
            logger.error("Could not parse ZIP info, using fallback")
            return 0

        # Get actual ZIP file size
        total_zip_size = os.path.getsize(zip_file_path)

        # Metadata size is the difference between ZIP file size and compressed content size
        # ZIP file = compressed content + metadata (headers, directory structure, etc.)
        metadata_size = total_zip_size - total_compressed

        if metadata_size < 0:
            logger.warning(
                f"Negative metadata size calculated: {metadata_size}. ZIP size: {total_zip_size}, Compressed content: {total_compressed}"
            )
            return 0

        return metadata_size

    except Exception as e:
        logger.error(f"Error calculating ZIP metadata size: {e}")
        return 0

    finally:
        if zip_file_path.exists():
            zip_file_path.unlink()
        if zip_info_file_path.exists():
            zip_info_file_path.unlink()


def _lzfse_content_size_for_bundle(bundle_url: Path) -> int:
    total_lzfse_size = 0

    for file_path in bundle_url.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.is_symlink():
            continue

        compressed = _lzfse_compressed_size(file_path)
        total_lzfse_size += compressed

    return total_lzfse_size


def _get_extra_code_signature_size(bundle_url: Path) -> int:
    """Calculate additional space needed for code signature."""

    # TODO: Implement actual code signature size calculation
    return 0
