import hashlib
import os

from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo, TreemapType
from launchpad.size.models.insights import (
    DuplicateFileGroup,
    DuplicateFilesInsightResult,
)


class DuplicateFilesInsight(Insight[DuplicateFilesInsightResult]):
    EXTENSION_ALLOWLIST = [".xcprivacy"]

    # Make sure to group all duplicates in a directory that has one of these extensions
    DIRECTORY_EXTENSIONS = [".bundle"]

    def generate(self, input: InsightsInput) -> DuplicateFilesInsightResult | None:
        groups: List[DuplicateFileGroup] = []
        total_savings = 0

        covered_containers: set[str] = set()
        for infos in self._duplicate_directories(input.file_analysis.files).values():
            if len(infos) < 2:
                continue

            infos.sort(key=lambda f: (-f.size, f.path))
            group_size = sum(fi.size for fi in infos)
            savings = group_size - infos[0].size
            if savings <= 0:
                continue

            groups.append(
                DuplicateFileGroup(
                    filename=os.path.basename(infos[0].path),
                    files=infos,
                    total_savings=savings,
                )
            )
            total_savings += savings
            for info in infos:
                covered_containers.add(info.path)

        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for f in input.file_analysis.files:
            if (
                f.hash_md5
                and not self._is_allowed_extension(f.path)
                and not any(f.path.startswith(c + "/") or f.path == c for c in covered_containers)  # ← NEW GUARD
            ):
                files_by_hash[f.hash_md5].append(f)

        for dup_files in files_by_hash.values():
            if len(dup_files) < 2:
                continue

            dup_files.sort(key=lambda f: (-f.size, f.path))
            savings = sum(f.size for f in dup_files) - dup_files[0].size
            if savings <= 0:
                continue

            container = self._directory_grouping(dup_files[0].path)
            name = os.path.basename(container) if container else os.path.basename(dup_files[0].path)

            groups.append(
                DuplicateFileGroup(
                    filename=name,
                    files=dup_files,
                    total_savings=savings,
                )
            )
            total_savings += savings

        groups.sort(key=lambda g: (-g.total_savings, g.filename))

        if len(groups) > 0:
            return DuplicateFilesInsightResult(groups=groups, total_savings=total_savings)

        return None

    def _is_allowed_extension(self, file_path: str) -> bool:
        return any(file_path.endswith(ext) for ext in self.EXTENSION_ALLOWLIST)

    def _directory_grouping(self, file_path: str) -> str | None:
        p = Path(file_path)
        for i, part in enumerate(p.parts):
            if any(part.endswith(ext) for ext in self.DIRECTORY_EXTENSIONS):
                return str(Path(*p.parts[: i + 1]))
        return None

    def _duplicate_directories(self, files: List[FileInfo]) -> Dict[str, List[FileInfo]]:
        dir_to_children: Dict[str, List[FileInfo]] = defaultdict(list)
        for f in files:
            if f.hash_md5:
                root = self._directory_grouping(f.path)
                if root:
                    dir_to_children[root].append(f)

        dup_dirs: Dict[str, List[FileInfo]] = defaultdict(list)
        for root, children in dir_to_children.items():
            if not children:
                continue

            md5 = hashlib.md5()
            for h in sorted(c.hash_md5 for c in children if c.hash_md5):
                md5.update(h.encode())
            folder_hash = md5.hexdigest()

            dup_dirs[folder_hash].append(
                FileInfo(
                    full_path=(
                        children[0].full_path.parent / root if children[0].full_path is not None else Path(root)
                    ),
                    path=root,
                    size=sum(c.size for c in children),
                    file_type="directory",
                    hash_md5=folder_hash,
                    treemap_type=TreemapType.FILES,
                    children=children,
                )
            )
        return dup_dirs
