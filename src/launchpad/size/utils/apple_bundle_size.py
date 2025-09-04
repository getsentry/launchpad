import os
import stat
import tempfile
import uuid
import zipfile

from pathlib import Path
from typing import Iterable, Tuple

import lzfse

from launchpad.parsers.apple.macho_parser import MachOParser
from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.utils.file_utils import get_file_size, to_nearest_block_size
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


def calculate_bundle_sizes(bundle_url: Path) -> Tuple[int, int]:
    """
    Calculate the download and install sizes for an Apple .app bundle.
    """
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
        "Bundle size breakdown - ZIP metadata: %d bytes, LZFSE content: %d bytes, "
        "Code signature: %d bytes, Total download: %d bytes, Total install: %d bytes",
        metadata_size,
        lzfse_size,
        signature_size,
        download_size,
        install_size,
    )

    return download_size, install_size


def _iter_regular_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        pdir = Path(dirpath)

        # Prune directory symlinks before we descend
        keep = []
        for d in dirnames:
            dp = pdir / d
            try:
                st = os.lstat(dp)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            keep.append(d)
        dirnames[:] = keep  # in-place mutation controls traversal

        for name in filenames:
            p = pdir / name
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                # Symlink entries contribute 0 installed bytes
                continue
            if stat.S_ISREG(st.st_mode):
                yield p
            # We ignore other special files (sockets, fifos, etc.)


def _calculate_app_store_size(bundle_url: Path) -> int:
    """
    Installed bytes = sum of allocated blocks for regular files only,
    rounded to APPLE_FILESYSTEM_BLOCK_SIZE. Directories/links count as 0.
    """
    total_size = 0
    file_count = 0

    for file_path in _iter_regular_files(bundle_url):
        file_count += 1

        try:
            # Use actual byte size, then round to block size for on-disk accounting
            raw = get_file_size(file_path)
            total_size += to_nearest_block_size(raw, APPLE_FILESYSTEM_BLOCK_SIZE)

            # Optional extra code-signature slack for extension-less Mach-O binaries
            if not file_path.suffix and MachOParser.is_macho_binary(file_path):
                total_size += _get_extra_code_signature_size(file_path)
        except Exception as e:
            # Skip unreadable files but keep going
            logger.warning("Error getting file size for %s: %s", file_path, e)
            continue

    logger.info("App Store size calculation: %d files, %d bytes", file_count, total_size)
    return total_size


def _lzfse_content_size_for_bundle(bundle_url: Path) -> int:
    """
    Sum of LZFSE-compressed sizes for the bundle's regular files.
    (Symlinks and non-regular files are skipped.)
    """
    total = 0
    for file_path in _iter_regular_files(bundle_url):
        total += _lzfse_compressed_size(file_path)
    return total


def _lzfse_compressed_size(file_path: Path) -> int:
    """
    Return compressed size using lzfse; never larger than source length.
    On error, fall back to the file's byte size.
    """
    try:
        with open(file_path, "rb") as f:
            source = f.read()
        src_len = len(source)
        comp = lzfse.compress(source)  # type: ignore
        clen = len(comp)  # type: ignore
        return clen if clen < src_len else src_len
    except Exception as e:
        logger.error("Error compressing %s: %s", file_path, e)
        try:
            return get_file_size(file_path)
        except Exception:
            return 0


def _zip_metadata_size_for_bundle(bundle_url: Path) -> int:
    """
    Create a temporary ZIP (deflated) of the bundle and compute:
      metadata = on-disk ZIP size - sum(entry.compress_size)
    Using Python's zipfile for stable cross-platform behavior.

    Symlinks are skipped to mirror installed-bytes semantics. If you prefer to
    *store* symlinks as entries, set UNIX attributes on ZipInfo; omitted here
    for simplicity and determinism.
    """
    tmpdir = Path(tempfile.gettempdir())
    zip_path = tmpdir / f"{uuid.uuid4()}.zip"

    # We need archive names relative to the bundle's parent, so consumers see "<App>.app/..."
    archive_root = bundle_url.parent

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for file_path in _iter_regular_files(bundle_url):
                arcname = file_path.relative_to(archive_root).as_posix()
                # write() will stat again internally; file may disappear, so guard
                try:
                    zf.write(file_path, arcname)
                except FileNotFoundError:
                    continue

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                sum_compressed = sum(info.compress_size for info in zf.infolist())
        except zipfile.BadZipFile:
            logger.error("Temp ZIP unreadable; returning 0 metadata")
            return 0

        try:
            total_zip = os.path.getsize(zip_path)
        except OSError:
            return 0

        meta = total_zip - sum_compressed
        if meta < 0:
            logger.warning(
                "Negative ZIP metadata computed (%d). ZIP=%d, sum_compressed=%d",
                meta,
                total_zip,
                sum_compressed,
            )
            return 0
        return meta
    except Exception as e:
        logger.error("Error calculating ZIP metadata size: %s", e)
        return 0
    finally:
        try:
            zip_path.unlink()
        except FileNotFoundError:
            pass


def _get_extra_code_signature_size(_bundle_or_binary_path: Path) -> int:
    """
    Placeholder for additional code-signature headroom (if any).
    Keep at 0 unless you implement an empirical model.
    """
    return 0
