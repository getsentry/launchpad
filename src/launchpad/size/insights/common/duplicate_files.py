import os

from collections import defaultdict
from collections.abc import Sequence
from pathlib import PurePosixPath

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.common import AppComponent, FileInfo
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

        component_roots = self._component_roots(input.app_components)

        directories_by_scope: dict[str, list[FileInfo]] = defaultdict(list)
        files_by_scope: dict[str, list[FileInfo]] = defaultdict(list)

        for directory in directories:
            scope = self._scope_for_path(directory.path, component_roots)
            directories_by_scope[scope].append(directory)

        for file_info in all_files:
            scope = self._scope_for_path(file_info.path, component_roots)
            files_by_scope[scope].append(file_info)

        groups: list[FileSavingsResultGroup] = []
        total_savings = 0
        for scope in sorted(set(directories_by_scope) | set(files_by_scope)):
            scope_groups, scope_savings = self._generate_in_scope(
                directories=directories_by_scope[scope],
                all_files=files_by_scope[scope],
            )
            groups.extend(scope_groups)
            total_savings += scope_savings

        groups.sort(key=lambda g: (-g.total_savings, g.name))

        if groups:
            return DuplicateFilesInsightResult(groups=groups, total_savings=total_savings)
        return None

    def _generate_in_scope(
        self,
        *,
        directories: list[FileInfo],
        all_files: list[FileInfo],
    ) -> tuple[list[FileSavingsResultGroup], int]:
        groups: list[FileSavingsResultGroup] = []
        total_savings = 0
        covered_dirs: set[str] = set()
        covered_files: set[str] = set()

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
            dirs.sort(key=lambda d: (-self._dir_size(d), d.path))
            if len(dirs) < 2:
                continue

            group_size = sum(self._dir_size(d) for d in dirs)
            savings = group_size - self._dir_size(dirs[0])
            if savings <= 0:
                continue

            files_with_savings = [FileSavingsResult(file_path=d.path, total_savings=self._dir_size(d)) for d in dirs]
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
        files_by_hash: dict[str, list[FileInfo]] = defaultdict(list)
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

        return groups, total_savings

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _dir_size(d: FileInfo) -> int:
        """Get size_including_children for a directory, asserting it's set."""
        assert d.size_including_children is not None
        return d.size_including_children

    def _flatten_files(self, files: list[FileInfo]) -> list[FileInfo]:
        """Recursively flatten files, extracting nested children (e.g., assets within .car files)."""
        result: list[FileInfo] = []
        for f in files:
            result.append(f)
            if f.children:
                result.extend(self._flatten_files(f.children))
        return result

    def _directory_duplicate_candidates(self, directories: list[FileInfo]) -> list[list[FileInfo]]:
        """
        Returns a list of duplicate-directory groups (lists of FileInfo) where
        each group shares the same already-computed directory hash and has >= 2 members.
        """
        by_hash: dict[str, list[FileInfo]] = defaultdict(list)
        for f in directories:
            if f.hash and self._dir_size(f) >= self.MIN_DIR_SIZE_BYTES:
                by_hash[f.hash].append(f)

        return [dirs for dirs in by_hash.values() if len(dirs) > 1]

    def _is_allowed_extension(self, file_path: str) -> bool:
        return any(file_path.endswith(ext) for ext in self.EXTENSION_ALLOWLIST)

    @staticmethod
    def _is_under_any(path: str, containers: set[str]) -> bool:
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

    @classmethod
    def _any_path_under_any(cls, paths: list[str], containers: set[str]) -> bool:
        return any(cls._is_under_any(p, containers) for p in paths)

    @staticmethod
    def _min_depth(paths: list[str]) -> int:
        def depth(p: str) -> int:
            return 0 if not p else len(PurePosixPath(p).parts)

        return min(depth(p) for p in paths) if paths else 0

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = path
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized.rstrip("/")

    @classmethod
    def _normalize_component_root(cls, root: str) -> str:
        normalized = cls._normalize_path(root)
        if normalized == ".":
            return ""
        return normalized

    @classmethod
    def _component_roots(cls, components: Sequence[AppComponent]) -> list[str]:
        roots = {cls._normalize_component_root(component.path) for component in components} - {""}
        return sorted(
            roots,
            key=lambda root: (
                -len(PurePosixPath(root).parts),
                -len(root),
                root,
            ),
        )

    @classmethod
    def _scope_for_path(cls, path: str, roots: Sequence[str]) -> str:
        """Return the component root that owns *path*, or ``""`` for the main app.

        *roots* **must** be sorted deepest-first (as returned by
        ``_component_roots``) so that the longest prefix wins.
        """
        normalized_path = cls._normalize_path(path)
        for root in roots:
            if normalized_path == root or normalized_path.startswith(f"{root}/"):
                return root
        return ""
