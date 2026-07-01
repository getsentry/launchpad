"""Compute size differences between two analyses."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict

from launchpad.size.models.common import BaseAnalysisResults, FileInfo
from launchpad.size.models.diff import CategoryDiff, ChangeKind, FileChange, SizeDiffResults


def _build_label(results: BaseAnalysisResults) -> str:
    app_info = getattr(results, "app_info", None)
    if app_info is None:
        return "unknown"
    return f"{app_info.version} ({app_info.build})"


def _category_totals(results: BaseAnalysisResults) -> Dict[str, int]:
    totals: Dict[str, int] = defaultdict(int)
    for item in results.file_analysis.items:
        if item.is_dir:
            continue
        totals[item.treemap_type.value] += item.size
    return totals


def _file_sizes(results: BaseAnalysisResults) -> Dict[str, FileInfo]:
    # Top-level files only; nested children (e.g. assets inside a .car) roll up into their parent.
    return {item.path: item for item in results.file_analysis.items if not item.is_dir}


def compute_diff(base: BaseAnalysisResults, head: BaseAnalysisResults) -> SizeDiffResults:
    """Compare two size analyses and return the deltas from ``base`` to ``head``.

    Files are matched by path. A file present in both builds with a different content
    hash is reported as modified; hashes that match are omitted (no size change).
    """
    base_categories = _category_totals(base)
    head_categories = _category_totals(head)

    category_diffs = [
        CategoryDiff(
            category=category,
            head_size=head_categories.get(category, 0),
            base_size=base_categories.get(category, 0),
        )
        for category in base_categories.keys() | head_categories.keys()
    ]
    category_diffs = [c for c in category_diffs if c.size_diff != 0]
    category_diffs.sort(key=lambda c: abs(c.size_diff), reverse=True)

    base_files = _file_sizes(base)
    head_files = _file_sizes(head)

    file_changes: list[FileChange] = []
    for path in base_files.keys() | head_files.keys():
        base_file = base_files.get(path)
        head_file = head_files.get(path)

        if base_file is None and head_file is not None:
            file_changes.append(FileChange(path=path, kind=ChangeKind.ADDED, head_size=head_file.size, base_size=0))
        elif head_file is None and base_file is not None:
            file_changes.append(FileChange(path=path, kind=ChangeKind.REMOVED, head_size=0, base_size=base_file.size))
        elif base_file is not None and head_file is not None:
            if base_file.hash == head_file.hash and base_file.size == head_file.size:
                continue
            file_changes.append(
                FileChange(
                    path=path,
                    kind=ChangeKind.MODIFIED,
                    head_size=head_file.size,
                    base_size=base_file.size,
                )
            )

    file_changes.sort(key=lambda f: (abs(f.size_diff), f.path), reverse=True)

    return SizeDiffResults(
        app_name=getattr(getattr(head, "app_info", None), "name", "unknown"),
        base_label=_build_label(base),
        head_label=_build_label(head),
        base_install_size=base.install_size,
        head_install_size=head.install_size,
        base_download_size=base.download_size,
        head_download_size=head.download_size,
        category_diffs=category_diffs,
        file_changes=file_changes,
    )
