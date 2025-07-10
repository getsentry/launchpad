from __future__ import annotations

import re

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set

from launchpad.size.models.common import FileAnalysis, FileInfo
from launchpad.size.models.treemap import TreemapElement
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ThinningConfig:
    """Configuration for a particular device slice."""

    target_image_scale: str
    exclude_architectures: Set[str] = field(default_factory=set)
    exclude_platforms: Set[str] = field(default_factory=set)


class AppThinningSimulator:
    """Simulates App Store slicing for a given device configuration."""

    @classmethod
    def for_iphone_se(cls) -> "AppThinningSimulator":
        """Return a simulator configured for iPhone SE (2× Retina, arm64)."""
        return cls(
            ThinningConfig(
                target_image_scale="2x",
                exclude_architectures={"x86_64", "i386"},  # strip simulator slices
                exclude_platforms={"ipad"},  # remove iPad‑specific assets
            )
        )

    @classmethod
    def for_ipad_pro_12_9(cls) -> "AppThinningSimulator":
        """Return a simulator for 12.9‑inch iPad Pro (2× Retina)."""
        return cls(
            ThinningConfig(
                target_image_scale="2x",
                exclude_architectures={"x86_64", "i386"},
                exclude_platforms={"iphone"},
            )
        )

    IMAGE_SCALE_PATTERNS = {
        scale: re.compile(rf"@{scale}\\.(png|jpe?g|webp)$", re.IGNORECASE) for scale in ("1x", "2x", "3x")
    }

    ARCHITECTURE_PATTERNS = {arch: re.compile(arch, re.IGNORECASE) for arch in ("arm64", "armv7", "x86_64", "i386")}

    PLATFORM_PATTERNS = {plat: re.compile(plat, re.IGNORECASE) for plat in ("iphone", "ipad", "universal")}

    def __init__(self, config: ThinningConfig):
        self.config = config

    def apply_thinning(self, analysis: FileAnalysis) -> FileAnalysis:
        logger.info(
            "Applying app‑thinning (scale=%s, exclude_arch=%s, exclude_platform=%s)",
            self.config.target_image_scale,
            sorted(self.config.exclude_architectures),
            sorted(self.config.exclude_platforms),
        )

        deduped = self._deduplicate(analysis.files)
        included: List[FileInfo] = []
        size_before = 0
        size_after = 0

        for f in deduped:
            size_before += f.size
            if self._should_include(f):
                included.append(f)
                size_after += f.size

        logger.info(
            "Thinning complete → kept %d/%d files (%.1f %%, %d → %d bytes)",
            len(included),
            len(analysis.files),
            100 * size_after / size_before if size_before else 0,
            size_before,
            size_after,
        )
        return FileAnalysis(files=included)

    def _deduplicate(self, files: List[FileInfo]) -> List[FileInfo]:
        """Remove *perfect* duplicates by (folder, filename, size)."""
        seen: Set[tuple[str, str, int]] = set()
        unique: List[FileInfo] = []

        for fi in files:
            key = (str(Path(fi.path).parent), Path(fi.path).name, fi.size)
            if key in seen:
                logger.debug("Skipping duplicate %s", fi.path)
                continue
            seen.add(key)
            unique.append(self._dedupe_children(fi))
        return unique

    def _dedupe_children(self, fi: FileInfo) -> FileInfo:
        if not fi.children:
            return fi
        child_seen: Set[tuple[str, int]] = set()
        dedup_children: List[TreemapElement] = []
        removed_size = 0
        for child in fi.children:
            k = (child.path or "", child.install_size)
            if k in child_seen:
                removed_size += child.install_size
                continue
            child_seen.add(k)
            dedup_children.append(child)
        if removed_size:
            logger.debug("Reduced %s by %d B (child dedup)", fi.path, removed_size)
        return FileInfo(
            full_path=fi.full_path,
            path=fi.path,
            size=fi.size - removed_size,
            file_type=fi.file_type,
            hash_md5=fi.hash_md5,
            treemap_type=fi.treemap_type,
            children=dedup_children,
        )

    def _should_include(self, fi: FileInfo) -> bool:
        name = Path(fi.path).name.lower()
        return self._scale_ok(name) and self._arch_ok(name) and self._platform_ok(name)

    def _scale_ok(self, name: str) -> bool:
        for scale, pat in self.IMAGE_SCALE_PATTERNS.items():
            if pat.search(name):
                return scale == self.config.target_image_scale
        return True  # untagged → keep

    def _arch_ok(self, name: str) -> bool:
        for arch, pat in self.ARCHITECTURE_PATTERNS.items():
            if pat.search(name):
                return arch not in self.config.exclude_architectures
        return True

    def _platform_ok(self, name: str) -> bool:
        for plat, pat in self.PLATFORM_PATTERNS.items():
            if pat.search(name):
                return plat not in self.config.exclude_platforms
        return True
