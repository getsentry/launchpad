import os

from collections import defaultdict
from pathlib import PurePosixPath
from typing import Dict, List, Set

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import FileInfo
from launchpad.size.models.insights import (
    DuplicateFilesInsightResult,
    FileSavingsResult,
    FileSavingsResultGroup,
)


class DuplicateFilesInsight(Insight[DuplicateFilesInsightResult]):
    EXTENSION_ALLOWLIST = [".xcprivacy", ".mobileprovision"]

    MIN_DIR_SIZE_BYTES = 0

    def generate(self, input: InsightsInput) -> DuplicateFilesInsightResult | None:
        files = input.file_analysis.files
        directories = input.file_analysis.directories
        all_files = self._flatten_files(files)

        groups: List[FileSavingsResultGroup] = []
        total_savings = 0
        covered_dirs: Set[str] = set()
        covered_files: Set[str] = set()

        # -----------------------------
        # 1) Duplicate DIRECTORIES
        # -----------------------------
        dir_groups = self._directory_duplicate_candidates(directories)

        # Process shallower (outer) groups first so we can suppress nested ones
        dir_groups.sort(key=lambda ds: self._min_depth([d.path for d in ds]))

        for dirs in dir_groups:
            # If any member of this group is under an already covered dir, skip whole group
            if self._any_path_under_any([d.path for d in dirs], covered_dirs):
                continue

            # Savings if we keep the largest one and dedupe the rest
            dirs.sort(key=lambda d: (-d.size, d.path))
            if len(dirs) < 2:
                continue

            group_size = sum(d.size for d in dirs)
            savings = group_size - dirs[0].size
            if savings <= 0:
                continue

            files_with_savings = [FileSavingsResult(file_path=d.path, total_savings=d.size) for d in dirs]
            groups.append(
                FileSavingsResultGroup(
                    name=os.path.basename(dirs[0].path) or "/",
                    files=files_with_savings,
                    total_savings=savings,
                )
            )
            total_savings += savings

            for d in dirs:
                covered_dirs.add(d.path)

        # -----------------------------
        # 2) Duplicate FILES
        # -----------------------------
        files_by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for f in all_files:
            if (
                not f.path.endswith("/Other")  # Skip synthetic /Other nodes
                and not self._is_under_any(f.path, covered_dirs)  # Skip files under duplicate dirs
                and f.hash
                and not self._is_allowed_extension(f.path)
            ):
                files_by_hash[f.hash].append(f)

        # Process hash groups by depth (shallowest first) to handle parent files before children
        for file_hash in sorted(files_by_hash, key=lambda h: self._min_depth([f.path for f in files_by_hash[h]])):
            dup_files = [f for f in files_by_hash[file_hash] if not self._is_under_any(f.path, covered_files)]

            if len(dup_files) < 2:
                continue

            dup_files.sort(key=lambda f: (-f.size, f.path))
            savings = sum(f.size for f in dup_files) - dup_files[0].size
            if savings <= 0:
                continue

            files_with_savings = [FileSavingsResult(file_path=f.path, total_savings=f.size) for f in dup_files]
            groups.append(
                FileSavingsResultGroup(
                    name=os.path.basename(dup_files[0].path),
                    files=files_with_savings,
                    total_savings=savings,
                )
            )
            total_savings += savings
            covered_files.update(f.path for f in dup_files if f.children)

        groups.sort(key=lambda g: (-g.total_savings, g.name))

        if groups:
            return DuplicateFilesInsightResult(groups=groups, total_savings=total_savings)
        return None

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _flatten_files(self, files: List[FileInfo]) -> List[FileInfo]:
        """Recursively flatten files, extracting nested children (e.g., assets within .car files)."""
        result: List[FileInfo] = []
        for f in files:
            result.append(f)
            if f.children:
                result.extend(self._flatten_files(f.children))
        return result

    def _directory_duplicate_candidates(self, directories: List[FileInfo]) -> List[List[FileInfo]]:
        """
        Returns a list of duplicate-directory groups (lists of FileInfo) where
        each group shares the same already-computed directory hash and has >= 2 members.
        """
        by_hash: Dict[str, List[FileInfo]] = defaultdict(list)
        for f in directories:
            if f.hash and f.size >= self.MIN_DIR_SIZE_BYTES:
                by_hash[f.hash].append(f)

        return [dirs for dirs in by_hash.values() if len(dirs) > 1]

    def _is_allowed_extension(self, file_path: str) -> bool:
        return any(file_path.endswith(ext) for ext in self.EXTENSION_ALLOWLIST)

    @staticmethod
    def _is_under_any(path: str, containers: Set[str]) -> bool:
        """Check if path or any of its parents are in containers (O(path_depth))."""
        if path in containers:
            return True
        # Walk up parent hierarchy: "a/b/c" checks "a" then "a/b"
        parts = path.split("/")
        for depth in range(1, len(parts)):
            parent_path = "/".join(parts[:depth])
            if parent_path in containers:
                return True
        return False

    @staticmethod
    def _any_path_under_any(paths: List[str], containers: Set[str]) -> bool:
        for p in paths:
            if DuplicateFilesInsight._is_under_any(p, containers):
                return True
        return False

    @staticmethod
    def _min_depth(paths: List[str]) -> int:
        def depth(p: str) -> int:
            return 0 if not p else len(PurePosixPath(p).parts)

        return min(depth(p) for p in paths) if paths else 0
