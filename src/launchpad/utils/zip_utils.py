"""Pure-Python zip archive creation.

Replaces shelling out to the Info-ZIP ``zip`` binary, which is not available in the
distroless runtime image.
"""

import os
import stat
import time
import zipfile

from pathlib import Path

# zipfile can't represent timestamps before 1980, so clamp anything older.
_MIN_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _zip_info_for(arcname: str, st: os.stat_result) -> zipfile.ZipInfo:
    date_time = time.localtime(st.st_mtime)[:6]
    info = zipfile.ZipInfo(arcname, date_time=max(date_time, _MIN_ZIP_TIMESTAMP))
    # Preserve unix permissions the same way Info-ZIP does (mode in the high 16 bits).
    info.external_attr = (stat.S_IMODE(st.st_mode) | stat.S_IFMT(st.st_mode)) << 16
    return info


def zip_directory(source_dir: Path, output_path: Path, *, preserve_symlinks: bool = True) -> None:
    """Recursively zip ``source_dir`` into ``output_path``.

    Mirrors ``zip -r`` (or ``zip -r -y`` when ``preserve_symlinks`` is set): entries are
    named relative to the parent of ``source_dir`` so the archive root is ``source_dir.name``,
    directory entries are included, and unix permissions are preserved.

    Args:
        source_dir: Directory to archive
        output_path: Destination ``.zip`` path (overwritten if it exists)
        preserve_symlinks: Store symlinks as symlink entries instead of following them
    """
    source_dir = Path(source_dir)
    base = source_dir.parent

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        _add_path(zf, source_dir, base, preserve_symlinks)


def _add_path(zf: zipfile.ZipFile, path: Path, base: Path, preserve_symlinks: bool) -> None:
    try:
        st = path.lstat() if preserve_symlinks else path.stat()
    except FileNotFoundError:
        # Dangling symlink while following links; Info-ZIP skips these too
        return
    arcname = path.relative_to(base).as_posix()

    if preserve_symlinks and stat.S_ISLNK(st.st_mode):
        info = _zip_info_for(arcname, st)
        zf.writestr(info, os.readlink(path))
        return

    if stat.S_ISDIR(st.st_mode):
        info = _zip_info_for(arcname + "/", st)
        info.external_attr |= 0x10  # MS-DOS directory flag, as Info-ZIP sets it
        zf.writestr(info, b"")
        for child in sorted(path.iterdir()):
            _add_path(zf, child, base, preserve_symlinks)
        return

    info = _zip_info_for(arcname, st)
    info.compress_type = zipfile.ZIP_DEFLATED
    with open(path, "rb") as src, zf.open(info, "w") as dst:
        while chunk := src.read(1024 * 1024):
            dst.write(chunk)
