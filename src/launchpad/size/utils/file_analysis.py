import hashlib
import logging

from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Dict, List

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import FILE_TYPE_TO_TREEMAP_TYPE, TreemapType
from launchpad.utils.file_utils import calculate_file_hash, get_file_size, to_nearest_block_size
from launchpad.utils.performance import trace

logger = logging.getLogger(__name__)


@trace("apple.analyze_files")
def analyze_apple_files(
    xcarchive: ZippedXCArchive,
    *,
    algo: str = "sha256",
    follow_symlinks: bool = False,
) -> FileAnalysis:
    """
    Analyze all files in the app bundle, computing content hashes for files
    and content-only hashes for directories (based on their children's hashes).
    """
    logger.debug("Analyzing files in app bundle")

    app_bundle_path = xcarchive.get_app_bundle_path()

    # These are filled during the walk (single pass for files/dirs)
    files: Dict[str, FileInfo] = {}
    dirs: Dict[str, FileInfo] = {}
    # Parent -> [child paths] (relative, posix)
    children_by_dir: Dict[str, List[str]] = defaultdict(list)

    # Ensure we include the root directory explicitly
    root_rel = ""  # represent root with empty string
    dirs[root_rel] = _make_directory_info(app_bundle_path, root_rel)

    # Walk everything
    for file_path in app_bundle_path.rglob("*"):
        # Optionally ignore symlinks (often safer for bundle analysis)
        try:
            if file_path.is_symlink() and not follow_symlinks:
                continue
        except OSError:
            # Broken symlink etc
            logger.warning("Skipping path due to OSError: %s", file_path)
            continue

        rel = file_path.relative_to(app_bundle_path).as_posix()  # "" for root not produced by rglob
        parent_rel = PurePosixPath(rel).parent.as_posix() if rel else root_rel

        if file_path.is_dir():
            di = _make_directory_info(file_path, rel)
            dirs[rel] = di
            children_by_dir[parent_rel].append(rel)
        elif file_path.is_file():
            size = to_nearest_block_size(get_file_size(file_path), APPLE_FILESYSTEM_BLOCK_SIZE)

            file_type = file_path.suffix.lower().lstrip(".")
            if not file_type:
                file_type = _detect_file_type(file_path)

            # File content hash
            file_hash = calculate_file_hash(file_path, algorithm=algo)

            children: List[FileInfo] = []
            if file_type == "car":
                children = _analyze_asset_catalog(xcarchive, Path(rel))
                children_size = sum(child.size for child in children)
                children.append(
                    FileInfo(
                        full_path=file_path,
                        path=f"{rel}/Other",
                        size=size - children_size,
                        file_type="unknown",
                        hash=file_hash,  # keep the same field name for BC, even if algo != md5
                        treemap_type=TreemapType.ASSETS,
                        is_dir=False,
                        children=[],
                    )
                )

            fi = FileInfo(
                full_path=file_path,
                path=rel,
                size=size,
                file_type=file_type or "unknown",
                hash=file_hash,
                treemap_type=FILE_TYPE_TO_TREEMAP_TYPE.get(file_type, TreemapType.FILES),
                is_dir=False,
                children=children,
            )
            files[rel] = fi
            children_by_dir[parent_rel].append(rel)
        else:
            # Neither file nor dir (fifo, socket, etc.) -> skip
            continue

    # Bottom-up hash all directories from deepest to root
    directories_with_hashes = _hash_directories_bottom_up(dirs, files, children_by_dir, algo=algo)

    return FileAnalysis(files=list(files.values()), directories=list(directories_with_hashes.values()))


def _make_directory_info(full_path: Path, rel: str) -> FileInfo:
    # size will be filled later as sum(children)
    return FileInfo(
        full_path=full_path,
        path=rel,
        size=0,
        file_type="directory",
        hash="",  # to be filled
        treemap_type=TreemapType.FILES,
        is_dir=True,
        children=[],
    )


def _hash_directories_bottom_up(
    dirs: Dict[str, FileInfo],
    files: Dict[str, FileInfo],
    children_by_dir: Dict[str, List[str]],
    *,
    algo: str,
) -> Dict[str, FileInfo]:
    # Sort dirs by depth (deepest first)
    def depth(p: str) -> int:
        return 0 if p == "" else len(PurePosixPath(p).parts)

    sorted_dirs = sorted(dirs.values(), key=lambda d: depth(d.path), reverse=True)
    updated: Dict[str, FileInfo] = {}

    # Pre-populate lookup for file hashes/sizes
    file_hash_lookup = {f.path: f.hash for f in files.values()}
    file_size_lookup = {f.path: f.size for f in files.values()}
    dir_hash_lookup: Dict[str, str] = {}
    dir_size_lookup: Dict[str, int] = {}

    for d in sorted_dirs:
        child_paths = children_by_dir.get(d.path, [])

        child_hashes: List[str] = []
        total_size = 0

        for child in child_paths:
            if child in files:
                child_hashes.append(file_hash_lookup[child])
                total_size += file_size_lookup[child]
            else:
                # child is a directory
                # If we visit deepest-first, the child dir hash should already be computed
                child_hashes.append(dir_hash_lookup[child])
                total_size += dir_size_lookup[child]

        # Empty dir -> stable, shared hash
        if not child_hashes:
            digest = hashlib.new(algo, b"empty_directory").hexdigest()
        else:
            # Only content hashes, sorted, so directory name changes don't matter
            h = hashlib.new(algo)
            for hexd in sorted(child_hashes):
                h.update(hexd.encode("utf-8"))
                h.update(b";")
            digest = h.hexdigest()

        updated_dir = FileInfo(
            full_path=d.full_path,
            path=d.path,
            size=total_size,
            file_type=d.file_type,
            hash=digest,
            treemap_type=d.treemap_type,
            is_dir=True,
            children=d.children,
        )
        updated[d.path] = updated_dir
        dir_hash_lookup[d.path] = digest
        dir_size_lookup[d.path] = total_size

    return updated


@trace("apple.analyze_asset_catalog")
def _analyze_asset_catalog(xcarchive: ZippedXCArchive, relative_path: Path) -> List[FileInfo]:
    """Analyze an asset catalog file."""
    catalog_details = xcarchive.get_asset_catalog_details(relative_path)
    result: List[FileInfo] = []
    for element in catalog_details:
        if element.full_path and element.full_path.exists() and element.full_path.is_file():
            # keep md5 field name for BC even if algo set to sha256 above
            file_hash = calculate_file_hash(element.full_path, algorithm="sha256")
        else:
            # not every element is backed by a file, so use imageId as hash
            file_hash = element.image_id

        result.append(
            FileInfo(
                full_path=element.full_path,
                path=str(relative_path / element.name),
                size=element.size,
                file_type=Path(element.full_path).suffix.lstrip(".") if element.full_path else "other",
                hash=file_hash,
                treemap_type=TreemapType.ASSETS,
                is_dir=False,
                children=[],
            )
        )
    return result


@trace("apple.detect_file_type")
def _detect_file_type(file_path: Path) -> str:
    """
    Detect file type using the `file` command only as a fallback.
    """
    import subprocess

    try:
        result = subprocess.run(["file", str(file_path)], capture_output=True, text=True, check=True)
        file_type = result.stdout.split(":", 1)[1].strip().lower()
        logger.debug("Detected file type for %s: %s", file_path, file_type)

        if "mach-o" in file_type:
            return "macho"
        if "executable" in file_type:
            return "executable"
        if "text" in file_type:
            return "text"
        if "directory" in file_type:
            return "directory"
        if "symbolic link" in file_type:
            return "symlink"
        if "hermes javascript bytecode" in file_type:
            return "hermes"
        if "empty" in file_type:
            return "empty"

        return file_type
    except subprocess.CalledProcessError as e:
        logger.warning("Failed to detect file type for %s: %s", file_path, e)
        return "unknown"
    except Exception as e:  # pragma: no cover – defensive
        logger.warning("Unexpected error detecting file type for %s: %s", file_path, e)
        return "unknown"
