import hashlib
import logging

from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Dict, List, Set, Tuple

import sentry_sdk

from launchpad.artifacts.apple.zipped_xcarchive import ZippedXCArchive
from launchpad.size.constants import APPLE_FILESYSTEM_BLOCK_SIZE
from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import FILE_TYPE_TO_TREEMAP_TYPE, TreemapType
from launchpad.utils.file_utils import calculate_file_hash, to_nearest_block_size

logger = logging.getLogger(__name__)

OMITTED_LEAF_NAME = "__omitted__"


@sentry_sdk.trace
def analyze_apple_files(
    xcarchive: ZippedXCArchive,
    max_depth: int | None = 1000,
) -> FileAnalysis:
    """
    Build a content-hashed, block-rounded file map of the app bundle.
    Directories are hashed from sorted child hashes. If `max_depth` is set,
    deeper subtrees are omitted from children but their sizes are aggregated
    into a single synthetic child, keeping parent sizes correct. This does not
    follow symlinks which are common in xcarchives.
    """
    import os

    logger.debug("Analyzing files in app bundle")

    app_bundle_path = xcarchive.get_app_bundle_path()

    files: Dict[str, FileInfo] = {}
    dirs: Dict[str, FileInfo] = {}
    children_by_dir: Dict[str, List[str]] = defaultdict(list)

    # register root
    root_rel = ""
    dirs[root_rel] = _make_directory_info(app_bundle_path, root_rel)

    # inode de-dup (dirs + files)
    seen_dir_inodes: Set[Tuple[int, int]] = set()
    seen_file_inodes: Set[Tuple[int, int]] = set()

    try:
        st_root = app_bundle_path.stat()
        seen_dir_inodes.add((st_root.st_dev, st_root.st_ino))
    except OSError as e:
        logger.warning("Failed stat on app bundle root %s: %s", app_bundle_path, e)

    omitted_hash = hashlib.new("sha256", b"omitted_subtree").hexdigest()

    for dirpath, dirnames, filenames in os.walk(app_bundle_path, followlinks=False):
        pdir = Path(dirpath)

        # compute normalized rel path of current directory
        rel_dir = pdir.relative_to(app_bundle_path).as_posix()
        if rel_dir in ("", "."):
            rel_dir = ""

        # Depth guard: aggregate omitted subtrees so parent sizes remain correct.
        if max_depth is not None:
            depth = 0 if rel_dir == "" else len(PurePosixPath(rel_dir).parts)
            if depth >= max_depth:
                for dname in dirnames:
                    child_path = pdir / dname
                    child_rel = child_path.relative_to(app_bundle_path).as_posix()
                    try:
                        agg_size = _dir_size_aggregate(
                            child_path,
                            seen_dirs=seen_dir_inodes,
                            seen_files=seen_file_inodes,
                        )
                    except Exception:
                        agg_size = 0

                    omitted_rel = f"{child_rel}/{OMITTED_LEAF_NAME}"
                    files[omitted_rel] = FileInfo(
                        full_path=child_path,
                        path=omitted_rel,
                        size=agg_size,
                        file_type="directory_omitted",
                        hash=omitted_hash,
                        treemap_type=TreemapType.FILES,
                        is_dir=False,
                        children=[],
                    )
                    # attach the synthetic node to the current dir
                    children_by_dir[rel_dir].append(omitted_rel)

                # stop descending further
                dirnames[:] = []

        # Prune symlinked/duplicate dirs by inode
        pruned: List[str] = []
        for dname in dirnames:
            dpath = pdir / dname
            try:
                if dpath.is_symlink():
                    continue
                st = dpath.stat(follow_symlinks=False)
                dinode = (st.st_dev, st.st_ino)
                if dinode in seen_dir_inodes:
                    continue
                seen_dir_inodes.add(dinode)
                pruned.append(dname)
            except OSError:
                logger.warning("Skipping inaccessible directory: %s", dpath)
                continue
        dirnames[:] = pruned

        # Ensure current dir exists
        dirs.setdefault(rel_dir, _make_directory_info(pdir, rel_dir))

        # Register child directories using their true rel path
        for dname in dirnames:
            dpath = pdir / dname
            child_rel = dpath.relative_to(app_bundle_path).as_posix()
            if child_rel == rel_dir:
                logger.warning("Self-referential directory edge at %s; skipping", child_rel)
                continue
            dirs[child_rel] = _make_directory_info(dpath, child_rel)
            children_by_dir[rel_dir].append(child_rel)

        # Files
        for fname in filenames:
            fpath = pdir / fname
            try:
                if fpath.is_symlink():
                    continue
            except OSError:
                logger.warning("Skipping path due to OSError: %s", fpath)
                continue

            try:
                st = fpath.stat(follow_symlinks=False)
                finode = (st.st_dev, st.st_ino)
                if finode in seen_file_inodes:
                    continue
                seen_file_inodes.add(finode)
                raw_size = st.st_size
            except OSError:
                logger.warning("Skipping path due to OSError: %s", fpath)
                continue

            rel = fpath.relative_to(app_bundle_path).as_posix()
            parent_rel = rel_dir

            size = to_nearest_block_size(raw_size, APPLE_FILESYSTEM_BLOCK_SIZE)

            file_type = fpath.suffix.lower().lstrip(".") or _detect_file_type(fpath)
            file_hash = calculate_file_hash(fpath, algorithm="sha256")

            children: List[FileInfo] = []
            if file_type == "car":
                children = _analyze_asset_catalog(xcarchive, Path(rel))
                children_size = sum(child.size for child in children)
                residual = max(0, size - children_size)
                if residual:
                    children.append(
                        FileInfo(
                            full_path=fpath,
                            path=f"{rel}/Other",
                            size=residual,
                            file_type="unknown",
                            hash=file_hash,
                            treemap_type=TreemapType.ASSETS,
                            is_dir=False,
                            children=[],
                        )
                    )

            files[rel] = FileInfo(
                full_path=fpath,
                path=rel,
                size=size,
                file_type=file_type or "unknown",
                hash=file_hash,
                treemap_type=FILE_TYPE_TO_TREEMAP_TYPE.get(file_type, TreemapType.FILES),
                is_dir=False,
                children=children,
            )
            children_by_dir[parent_rel].append(rel)

    directories_with_hashes = _hash_directories_bottom_up(dirs, files, children_by_dir, algo="sha256")

    all_items = list(files.values()) + list(directories_with_hashes.values())
    return FileAnalysis(items=all_items)


def _make_directory_info(full_path: Path, rel: str) -> FileInfo:
    dir_size = to_nearest_block_size(full_path.stat().st_size, APPLE_FILESYSTEM_BLOCK_SIZE)

    return FileInfo(
        full_path=full_path,
        path=rel,
        size=dir_size,
        file_type="directory",
        hash="",
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
    def depth(p: str) -> int:
        return 0 if p == "" else len(PurePosixPath(p).parts)

    sorted_dirs = sorted(dirs.values(), key=lambda d: depth(d.path), reverse=True)
    updated: Dict[str, FileInfo] = {}

    file_hash_lookup = {f.path: f.hash for f in files.values()}
    file_size_lookup = {f.path: f.size for f in files.values()}
    dir_hash_lookup: Dict[str, str] = {}
    dir_size_lookup: Dict[str, int] = {}

    for d in sorted_dirs:
        child_paths = children_by_dir.get(d.path, [])
        child_hashes: List[str] = []
        children_total_size = 0

        for child in child_paths:
            if child in files:
                child_hashes.append(file_hash_lookup[child])
                children_total_size += file_size_lookup[child]
            else:
                child_hashes.append(dir_hash_lookup[child])
                children_total_size += dir_size_lookup[child]

        if not child_hashes:
            digest = hashlib.new(algo, b"empty_directory").hexdigest()
        else:
            h = hashlib.new(algo)
            for hexd in sorted(child_hashes):
                h.update(hexd.encode("utf-8"))
                h.update(b";")
            digest = h.hexdigest()

        # Store just the directory's own entry size (not including children)
        # The treemap builder will add this to children's sum
        updated_dir = FileInfo(
            full_path=d.full_path,
            path=d.path,
            size=d.size,
            file_type=d.file_type,
            hash=digest,
            treemap_type=d.treemap_type,
            is_dir=True,
            children=d.children,
        )
        updated[d.path] = updated_dir
        dir_hash_lookup[d.path] = digest
        dir_size_lookup[d.path] = d.size + children_total_size

    return updated


@sentry_sdk.trace
def _analyze_asset_catalog(xcarchive: ZippedXCArchive, relative_path: Path) -> List[FileInfo]:
    """Analyze an asset catalog file into treemap children."""
    catalog_details = xcarchive.get_asset_catalog_details(relative_path)
    result: List[FileInfo] = []
    for element in catalog_details:
        if element.full_path and element.full_path.exists() and element.full_path.is_file():
            file_hash = calculate_file_hash(element.full_path, algorithm="sha256")
        elif element.content_hash:
            file_hash = element.content_hash
        else:
            file_hash = element.image_id

        result.append(
            FileInfo(
                full_path=element.full_path,
                path=str(relative_path / element.name),
                size=element.size,
                file_type=(Path(element.full_path or element.name).suffix.lstrip(".") or "other"),
                hash=file_hash,
                treemap_type=TreemapType.ASSETS,
                is_dir=False,
                children=[],
                idiom=element.idiom,
                colorspace=element.colorspace,
            )
        )
    return result


@sentry_sdk.trace
def _detect_file_type(file_path: Path) -> str:
    """Best-effort file type detection via `file` as a fallback."""
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


def _dir_size_aggregate(
    root: Path,
    seen_dirs: Set[Tuple[int, int]],
    seen_files: Set[Tuple[int, int]],
) -> int:
    """
    Return the rounded size of all unique files under `root`.
    Reuses `seen_*` sets so totals stay globally de-duplicated across the archive.
    """
    import os

    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        pdir = Path(dirpath)

        pruned: List[str] = []
        for dname in dirnames:
            dpath = pdir / dname
            try:
                if dpath.is_symlink():
                    continue
                st = dpath.stat(follow_symlinks=False)
                dinode = (st.st_dev, st.st_ino)
                if dinode in seen_dirs:
                    continue
                seen_dirs.add(dinode)
                pruned.append(dname)
            except OSError:
                continue
        dirnames[:] = pruned

        for fname in filenames:
            fpath = pdir / fname
            try:
                if fpath.is_symlink():
                    continue
                st = fpath.stat(follow_symlinks=False)
                finode = (st.st_dev, st.st_ino)
                if finode in seen_files:
                    continue
                seen_files.add(finode)
                total += to_nearest_block_size(st.st_size, APPLE_FILESYSTEM_BLOCK_SIZE)
            except OSError:
                continue

    return total
