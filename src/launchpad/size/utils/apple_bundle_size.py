import os
import plistlib
import subprocess
import tempfile
import uuid

from pathlib import Path
from typing import List, NamedTuple

import lzfse

from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.models.common import AppComponent, ComponentType
from launchpad.utils.file_utils import get_file_size, to_nearest_block_size
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class ComponentSizes(NamedTuple):
    """Size information for a component."""

    download_size: int
    install_size: int


class ComponentInfo(NamedTuple):
    """Information about a single component."""

    path: Path
    app_id: str
    download_size: int
    install_size: int


class ComponentsWithSizes(NamedTuple):
    """Aggregated size information with component breakdown."""

    total_download: int
    total_install: int
    components: List[ComponentInfo]


class BundleSizes(NamedTuple):
    """Complete bundle size information with all components."""

    total_download: int
    total_install: int
    app_components: List[AppComponent]


def calculate_bundle_sizes(
    bundle_url: Path,
    main_app_name: str,
    main_app_id: str,
) -> BundleSizes:
    """
    Calculate the download and install sizes for an Apple app bundle with component breakdown.
    """

    if not bundle_url.exists():
        raise ValueError(f"Bundle not found: {bundle_url}")

    if bundle_url.suffix != ".app":
        raise ValueError(f"Only .app bundles are supported, got: {bundle_url}")

    install_size = _calculate_install_size(bundle_url)
    lzfse_size = _calculate_lzfse_size(bundle_url)
    metadata_size = _zip_metadata_size_for_bundle(bundle_url)
    download_size = lzfse_size + metadata_size

    logger.debug(
        f"Bundle size breakdown - "
        f"ZIP metadata: {metadata_size} bytes, "
        f"LZFSE content: {lzfse_size} bytes, "
        f"Total download: {download_size} bytes, "
        f"Total install: {install_size} bytes"
    )

    watch_sizes = _calculate_watch_component_sizes(bundle_url)

    main_download = download_size - watch_sizes.total_download
    main_install = install_size - watch_sizes.total_install

    app_components: List[AppComponent] = [
        AppComponent(
            component_type=ComponentType.MAIN_ARTIFACT,
            app_id=main_app_id,
            name=main_app_name,
            path=".",
            download_size=main_download,
            install_size=main_install,
        )
    ]

    for watch_path, watch_app_id, watch_download_size, watch_install_size in watch_sizes.components:
        relative_path = str(watch_path.relative_to(bundle_url))
        app_components.append(
            AppComponent(
                component_type=ComponentType.WATCH_ARTIFACT,
                app_id=watch_app_id,
                name=watch_path.stem,
                path=relative_path,
                download_size=watch_download_size,
                install_size=watch_install_size,
            )
        )

        logger.info(
            "size.apple.watch_app_sizes",
            extra={
                "watch_app_name": watch_path.stem,
                "download_size": watch_download_size,
                "install_size": watch_install_size,
            },
        )

    logger.info(
        "size.apple.bundle_sizes",
        extra={
            "main_app_download_size": main_download,
            "main_app_install_size": main_install,
            "total_download_size": download_size,
            "total_install_size": install_size,
            "watch_app_count": len(app_components) - 1,
        },
    )

    return BundleSizes(
        total_download=download_size,
        total_install=install_size,
        app_components=app_components,
    )


def _calculate_component_sizes(component_path: Path) -> ComponentSizes:
    """Calculate the download and install sizes for a specific component (subdirectory) within a bundle."""

    if not component_path.exists():
        raise ValueError(f"Component path not found: {component_path}")

    if not component_path.is_dir():
        raise ValueError(f"Component path must be a directory: {component_path}")

    install_size = _calculate_install_size(component_path)
    download_size = _calculate_lzfse_size(component_path)

    logger.debug(
        f"Component {component_path.name} size - Download: {download_size} bytes, Install: {install_size} bytes"
    )

    return ComponentSizes(download_size=download_size, install_size=install_size)


def _calculate_watch_component_sizes(bundle_path: Path) -> ComponentsWithSizes:
    """Calculate sizes for all watch app components in a bundle."""

    watch_apps = list(bundle_path.rglob("Watch/*.app"))

    if not watch_apps:
        return ComponentsWithSizes(total_download=0, total_install=0, components=[])

    components: List[ComponentInfo] = []
    total_download = 0
    total_install = 0

    for watch_app_path in watch_apps:
        if not watch_app_path.is_dir():
            continue

        watch_plist_path = watch_app_path / "Info.plist"
        app_id = ""
        if watch_plist_path.exists():
            try:
                with open(watch_plist_path, "rb") as f:
                    watch_plist = plistlib.load(f)
                app_id = watch_plist.get("CFBundleIdentifier", "")
            except Exception:
                logger.exception("Error reading Info.plist for watch app")

        sizes = _calculate_component_sizes(watch_app_path)
        components.append(
            ComponentInfo(
                path=watch_app_path,
                app_id=app_id,
                download_size=sizes.download_size,
                install_size=sizes.install_size,
            )
        )
        total_download += sizes.download_size
        total_install += sizes.install_size

    # Calculate Watch/ directory overhead and divide evenly across watch apps
    watch_dir = bundle_path / "Watch"
    if watch_dir.exists() and components:
        watch_dir_overhead = to_nearest_block_size(get_file_size(watch_dir), APPLE_FILESYSTEM_BLOCK_SIZE)

        # Divide overhead evenly, first component gets remainder
        overhead_per_app = watch_dir_overhead // len(components)
        overhead_remainder = watch_dir_overhead % len(components)

        updated_components = []
        for i, (path, app_id, download, install) in enumerate(components):
            # First component gets remainder
            if i == 0:
                install += overhead_per_app + overhead_remainder
            else:
                install += overhead_per_app
            updated_components.append(ComponentInfo(path, app_id, download, install))

        components = updated_components
        total_install += watch_dir_overhead

    return ComponentsWithSizes(
        total_download=total_download,
        total_install=total_install,
        components=components,
    )


def _calculate_lzfse_size(path: Path) -> int:
    """Calculate LZFSE compressed size for all files in a directory."""
    total_lzfse_size = 0

    for file_path in path.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.is_symlink():
            continue

        compressed = _lzfse_compressed_size(file_path)
        total_lzfse_size += compressed

    logger.debug(f"LZFSE size for {path.name}: {total_lzfse_size} bytes")
    return total_lzfse_size


def _lzfse_compressed_size(file_path: Path) -> int:
    try:
        with open(file_path, "rb") as f:
            source_data = f.read()

        source_size = len(source_data)

        compressed_data = lzfse.compress(source_data)  # type: ignore
        compressed_size = len(compressed_data)  # type: ignore

        return compressed_size if compressed_size < source_size else source_size

    except Exception:
        logger.exception(f"Error lzfse compressing file {file_path}")
        return os.path.getsize(file_path)


def _calculate_install_size(path: Path) -> int:
    """Calculate install size by summing file sizes rounded to block size."""

    total_size = 0
    file_count = 0

    # Include the root directory's own entry size
    root_dir_size = to_nearest_block_size(get_file_size(path), APPLE_FILESYSTEM_BLOCK_SIZE)
    total_size += root_dir_size

    for file_path in path.rglob("*"):
        if file_path.is_symlink():
            continue

        file_count += 1
        file_size = to_nearest_block_size(get_file_size(file_path), APPLE_FILESYSTEM_BLOCK_SIZE)
        total_size += file_size

    logger.debug(f"Install size for {path.name}: {file_count} files, {total_size} bytes")
    return total_size


def _zip_metadata_size_for_bundle(bundle_url: Path) -> int:
    temp_dir = Path(tempfile.gettempdir())
    zip_file_path = temp_dir / f"{uuid.uuid4()}.zip"
    zip_info_file_path = temp_dir / f"{uuid.uuid4()}.txt"
    bundle_dir = bundle_url.parent
    bundle_name = bundle_url.name

    try:
        logger.debug(f"Creating ZIP file: zip -r {zip_file_path} {bundle_name}")
        result = subprocess.run(
            ["zip", "-r", str(zip_file_path), str(bundle_name)],
            shell=False,
            capture_output=True,
            text=True,
            cwd=str(bundle_dir),
        )
        if result.returncode != 0:
            logger.error(f"ZIP command failed: {result.stderr}")
            return 0

        logger.debug(f"Getting ZIP info: unzip -v {zip_file_path}")
        with open(zip_info_file_path, "w") as zip_info_file:
            result = subprocess.run(
                ["unzip", "-v", str(zip_file_path)],
                shell=False,
                stdout=zip_info_file,
                stderr=subprocess.PIPE,
                text=True,
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

    except Exception:
        logger.exception("Error calculating ZIP metadata size")
        return 0

    finally:
        if zip_file_path.exists():
            zip_file_path.unlink()
        if zip_info_file_path.exists():
            zip_info_file_path.unlink()
