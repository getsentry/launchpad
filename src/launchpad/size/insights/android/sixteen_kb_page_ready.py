"""16KB page ready insight for Android apps."""

from pathlib import Path

import lief

from launchpad.size.insights.insight import Insight, InsightsInput
from launchpad.size.models.insights import SixteenKBPageReadyInsightResult
from launchpad.utils.logging import get_logger

logger = get_logger(__name__)


class SixteenKBPageReadyInsight(Insight[SixteenKBPageReadyInsightResult]):
    """Analyze whether Android app is ready for 16KB page size devices.

    This insight checks ELF section alignment in native libraries (.so files) for
    arm64-v8a and x86_64 architectures. For 16KB page compatibility, all ELF sections
    with alignment requirements must be aligned to at least 16KB (2^16 bytes).

    Only arm64-v8a and x86_64 architectures need to be aligned for 16KB page compatibility.
    """

    # Architectures that need 16KB alignment
    TARGET_ARCHITECTURES = {"arm64-v8a", "x86_64"}

    def generate(self, input: InsightsInput) -> SixteenKBPageReadyInsightResult | None:
        """Check if the app is ready for 16KB page sizes."""
        unaligned_files: list[str] = []

        # Find all .so files in the relevant architectures
        for file_info in input.file_analysis.files:
            if not file_info.path.endswith(".so"):
                continue

            # Extract architecture from path (lib/<arch>/*.so)
            path_parts = Path(file_info.path).parts
            if len(path_parts) < 3 or path_parts[0] != "lib":
                continue

            arch = path_parts[1]
            if arch not in self.TARGET_ARCHITECTURES:
                logger.debug(f"Skipping {file_info.path} - architecture {arch} not in target architectures")
                continue

            # Check ELF alignment using the actual file path
            if self._check_elf_alignment(file_info.full_path, file_info.path):
                unaligned_files.append(file_info.path)
                logger.debug(f"Found unaligned file: {file_info.path}")

        is_ready = len(unaligned_files) == 0
        logger.info(f"16KB page ready analysis complete: ready={is_ready}, unaligned_files={len(unaligned_files)}")

        return SixteenKBPageReadyInsightResult(
            is_16kb_ready=is_ready,
            unaligned_files=unaligned_files,
            total_unaligned_files=len(unaligned_files),
        )

    def _check_elf_alignment(self, file_path: Path, relative_path: str) -> bool:
        """Check if an ELF file has proper 16KB alignment.

        Args:
            file_path: Absolute path to the ELF file
            relative_path: Relative path for logging

        Returns:
            True if the file has alignment issues, False if properly aligned
        """
        try:
            # Parse the ELF file using LIEF
            elf_binary = lief.parse(str(file_path))
            if not elf_binary:
                logger.warning(f"Could not parse ELF file {relative_path}")
                return False

            # Check each section's alignment
            for section in elf_binary.sections:
                # LIEF sections might not have alignment attribute or it might be None
                alignment = getattr(section, "alignment", None)
                if alignment is None:
                    continue

                # 0 or 1 means no alignment restriction
                if alignment <= 1:
                    continue

                # Check if alignment is >= 16KB (2^16)
                if alignment >= 16 * 1024:  # 16KB = 16384 bytes
                    continue

                logger.warning(
                    f"Android .so unaligned: {relative_path} section '{getattr(section, 'name', 'unknown')}' "
                    f"alignment={alignment} (needs >= 16384)"
                )
                return True

            return False

        except Exception as e:
            logger.error(f"Error analyzing ELF file {relative_path}: {e}")
            # Don't consider it unaligned if we can't parse it
            return False
